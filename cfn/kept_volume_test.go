package cfn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The interleaved create (a stack with a custom resource) names around a retained leftover the same way,
// and what later resources read (a Ref passed to the custom resource) is the new name.
func TestDeployInterleaved_RetainedLeftoverIsNamedAround(t *testing.T) {
	tmpl := []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn, Bucket: !Ref Data }
`)
	f := &listingFake{fakeApplier: &fakeApplier{}}
	opts := deployOpts()
	status := "FAILED"
	var gotBucket any
	opts.Invoke = func(_ context.Context, _, _ string, event []byte) (map[string]any, error) {
		var ev map[string]any
		_ = json.Unmarshal(event, &ev)
		if p, _ := ev["ResourceProperties"].(map[string]any); p != nil {
			gotBucket = p["Bucket"]
		}
		return map[string]any{"Status": status, "Reason": "boom"}, nil
	}
	if _, err := Deploy(context.Background(), tmpl, opts, f); err == nil {
		t.Fatal("test premise: the first create fails")
	}
	if _, ok := f.liveSpecs["Bucket/s-data"]; !ok {
		t.Fatal("test premise: the rollback keeps the Retain bucket")
	}
	f.stored, status = nil, "SUCCESS"
	rec, err := Deploy(context.Background(), tmpl, opts, f)
	if err != nil {
		t.Fatalf("re-created interleaved stack: %v", err)
	}
	name := recordedName(rec, "Data")
	if name == "s-data" || !strings.HasPrefix(name, "s-data-") {
		t.Fatalf("the re-created bucket must be named around the retained one, got %q", name)
	}
	bucket := ""
	for _, r := range rec.Resources {
		if r.LogicalID == "Data" {
			bucket = bucketNameOf(r)
		}
	}
	retained, _ := f.liveSpecs["Bucket/s-data"]["bucketName"].(string)
	if gotBucket != bucket || bucket == "" || bucket == retained {
		t.Fatalf("the custom resource got Bucket %v, want the new bucket's S3 name %q (not the retained bucket's %q)", gotBucket, bucket, retained)
	}
}

// keptVolumeTmpl is an instance with an encrypted data volume it keeps past its end (DeleteOnTermination:
// false, the stack's default key) and one it does not, plus a key created after the instance (failOn makes
// the create fail there and roll back).
const keptVolumeTmpl = `
Resources:
  Db:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings:
        - DeviceName: /dev/sdf
          Ebs: { VolumeSize: 20, Encrypted: true, DeleteOnTermination: false }
        - DeviceName: /dev/sdg
          Ebs: { VolumeSize: 5, DeleteOnTermination: true }
  After:
    Type: AWS::KMS::Key
    DependsOn: Db
`

// A DeleteOnTermination: false data mapping is a kind: Volume of its own, attached to the VM by its device
// name and retained; the other mapping stays a data disk; the default key that encrypts the kept volume is
// retained too.
func TestTranslate_EC2Instance_DeleteOnTerminationFalseIsAKeptVolume(t *testing.T) {
	m, fs := translateIn(t, keptVolumeTmpl, "Db", nil)
	if len(fs) != 0 {
		t.Fatalf("findings: %s", findingsText(fs))
	}
	dds, _ := m.Spec["dataDisks"].([]map[string]any)
	if len(dds) != 1 || dds[0]["name"] != "sdg" {
		t.Fatalf("only the DeleteOnTermination: true mapping is a data disk, got %#v", m.Spec["dataDisks"])
	}
	vols, _ := m.Spec["volumes"].([]any)
	if len(vols) != 1 {
		t.Fatalf("the kept volume must be attached, got %#v", m.Spec["volumes"])
	}
	att := vols[0].(map[string]any)
	if att["deviceName"] != "/dev/sdf" {
		t.Fatalf("the kept volume keeps its device name: %#v", att)
	}
	var kept, key *Manifest
	for _, x := range m.Extra {
		switch x.Kind {
		case "Volume":
			kept = x
		case "EncryptionKey":
			key = x
		}
	}
	if kept == nil || kept.Name != att["name"] || kept.DeletionPolicy != "Retain" {
		t.Fatalf("the kept volume must be a retained kind: Volume named as attached, got %#v", kept)
	}
	if kept.Spec["size"] != "20Gi" || kept.Spec["encrypted"] != true || key == nil || kept.Spec["encryptionKey"] != key.Name {
		t.Fatalf("the kept volume keeps its size and encryption: %#v (key %#v)", kept.Spec, key)
	}
	if key.DeletionPolicy != "Retain" {
		t.Fatalf("the default key that encrypts a kept volume must be retained, got %q", key.DeletionPolicy)
	}
	for i, x := range m.Extra {
		if x.Kind == "Volume" {
			for _, y := range m.Extra[i:] {
				if y.Kind == "EncryptionKey" {
					t.Fatal("the key must be applied before the volume it encrypts")
				}
			}
		}
	}
}

// A rolled-back create keeps the volume (as AWS keeps it when the instance is terminated), and its key; the
// re-created stack gets a new volume beside it, and so does a stack delete leave the volume.
func TestDeploy_DeleteOnTerminationFalse_SurvivesRollbackAndDelete(t *testing.T) {
	f := &listingFake{fakeApplier: &fakeApplier{failOn: "EncryptionKey/s-after"}}
	rec, err := Deploy(context.Background(), []byte(keptVolumeTmpl), deployOpts(), f)
	if err == nil {
		t.Fatal("test premise: the create fails and rolls back")
	}
	var vol, key string
	for _, r := range rec.Resources {
		switch {
		case r.Kind == "Volume":
			vol = "Volume/" + r.Name
		case r.Kind == "EncryptionKey" && strings.HasPrefix(r.LogicalID, "Db/"):
			key = "EncryptionKey/" + r.Name
		}
	}
	if vol == "" || key == "" {
		t.Fatalf("test premise: the record lists the kept volume and the key: %#v", rec.Resources)
	}
	if contains(f.deleted, vol) || contains(f.deleted, key) {
		t.Fatalf("the rollback deleted the kept volume or its key: %v", f.deleted)
	}
	if !contains(f.deleted, "VirtualMachine/s-db") {
		t.Fatalf("test premise: the rollback deleted the instance: %v", f.deleted)
	}

	f.stored, f.failOn = nil, ""
	rec2, err := Deploy(context.Background(), []byte(keptVolumeTmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("re-creating the stack beside the kept volume: %v", err)
	}
	for _, r := range rec2.Resources {
		if (r.Kind == "Volume" && "Volume/"+r.Name == vol) || (r.Kind == "EncryptionKey" && "EncryptionKey/"+r.Name == key) {
			t.Fatalf("the re-created stack took over %s/%s, which the rolled-back one kept", r.Kind, r.Name)
		}
	}

	f.deleted = nil
	if _, err := Destroy(context.Background(), deployOpts(), f); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	for _, d := range f.deleted {
		if strings.HasPrefix(d, "Volume/") {
			t.Fatalf("a stack delete deleted a kept volume: %v", f.deleted)
		}
	}
	if !contains(f.deleted, "VirtualMachine/s-db") {
		t.Fatalf("test premise: the delete removed the instance: %v", f.deleted)
	}
}

// An instance the stack already created with the mapping as a data disk keeps it as a data disk: an update
// must not move the disk to a kept volume (that would replace it and lose its data).
func TestUpdate_DeleteOnTerminationFalse_ExistingDataDiskStays(t *testing.T) {
	tmpl := `
Resources:
  Db:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings:
        - DeviceName: /dev/sdf
          Ebs: { VolumeSize: 20, DeleteOnTermination: false }
`
	prior := []StackResource{{LogicalID: "Db", APIVersion: "openinfra.dev/v1", Kind: "VirtualMachine", Name: "s-db",
		Spec: map[string]any{"os": "ubuntu-24.04", "dataDisks": []any{map[string]any{"name": "sdf", "size": "20Gi", "deviceName": "/dev/sdf"}}}}}
	opts := deployOpts()
	opts.prior = prior
	built, err := buildManifests([]byte(tmpl), opts)
	if err != nil {
		t.Fatal(err)
	}
	vm := built[0].res
	dds, _ := vm.Spec["dataDisks"].([]map[string]any)
	if len(dds) != 1 || dds[0]["name"] != "sdf" || vm.Spec["volumes"] != nil || len(built) != 1 {
		t.Fatalf("the recorded data disk must stay a data disk (no kept volume): %#v, %d objects", vm.Spec, len(built))
	}
	// A new stack gets the kept volume.
	built, err = buildManifests([]byte(tmpl), deployOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(built) != 2 || built[1].res.Kind != "Volume" || built[1].res.DeletionPolicy != "Retain" {
		t.Fatalf("a new stack's instance gets a retained kind: Volume, got %d objects", len(built))
	}
}
