package testcluster_test

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/testcluster"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

func TestWaitForResources(t *testing.T) {
	depFeature := features.New("appsv1/deployment").WithLabel("env", "dev").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// create a deployment
			deployment := newDeployment(cfg.Namespace(), "test-deployment", 10)
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Resources().Create(ctx, deployment); err != nil {
				t.Fatal(err)
			}
			return ctx
		}).
		Assess("deployment >=50% available", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatal(err)
			}
			dep := appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deployment", Namespace: cfg.Namespace()},
			}
			// wait for the deployment to become at least 50%
			err = wait.For(conditions.New(client.Resources()).ResourceMatch(&dep, func(object k8s.Object) bool {
				d := object.(*appsv1.Deployment)
				return float64(d.Status.ReadyReplicas)/float64(*d.Spec.Replicas) >= 0.50
			}), wait.WithTimeout(time.Minute*1))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("deployment availability: %.2f%%", float64(dep.Status.ReadyReplicas)/float64(*dep.Spec.Replicas)*100)
			return ctx
		}).
		Assess("deployment available", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatal(err)
			}
			dep := appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deployment", Namespace: cfg.Namespace()},
			}
			// wait for the deployment to finish becoming available
			err = wait.For(conditions.New(client.Resources()).DeploymentConditionMatch(&dep, appsv1.DeploymentAvailable, v1.ConditionTrue), wait.WithTimeout(time.Minute*1))
			if err != nil {
				t.Fatal(err)
			}
			return ctx
		}).
		Assess("deployment pod garbage collection", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatal(err)
			}
			// get list of pods
			var pods v1.PodList
			err = client.Resources(cfg.Namespace()).List(context.TODO(), &pods, resources.WithLabelSelector(labels.FormatLabels(map[string]string{"app": "wait-for-resources"})))
			if err != nil {
				t.Fatal(err)
			}
			// delete the deployment
			dep := appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deployment", Namespace: cfg.Namespace()},
			}
			err = client.Resources(cfg.Namespace()).Delete(context.TODO(), &dep)
			if err != nil {
				t.Fatal(err)
			}
			// wait for the deployment pods to be deleted
			err = wait.For(conditions.New(client.Resources()).ResourcesDeleted(&pods), wait.WithTimeout(time.Minute*1))
			if err != nil {
				t.Fatal(err)
			}
			return ctx
		}).Feature()

	testcluster.Env.Test(t, depFeature)
}

func newDeployment(namespace string, name string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"app": "wait-for-resources"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "wait-for-resources"},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "wait-for-resources"}},
				Spec:       v1.PodSpec{Containers: []v1.Container{{Name: "nginx", Image: "nginx"}}},
			},
		},
	}
}

func TestMain(m *testing.M) {
	testcluster.Main(m)
}
