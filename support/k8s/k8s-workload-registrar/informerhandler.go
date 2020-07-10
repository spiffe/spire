package main

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

type InformerHandlerConfig struct {
	Log        logrus.FieldLogger
	Controller *Controller
	Factory    informers.SharedInformerFactory
}

type InformerHandler struct {
	c InformerHandlerConfig
}

func NewInformerHandler(config InformerHandlerConfig) *InformerHandler {
	return &InformerHandler{
		c: config,
	}
}

func (ih *InformerHandler) addHandler(ctx context.Context, pod *corev1.Pod) {
	log := ih.c.Log.WithFields(logrus.Fields{
		"ns":  pod.Namespace,
		"pod": pod.Name,
	})
	if err := ih.c.Controller.SyncPod(ctx, pod); err != nil {
		log.WithError(err).Error("Failed to sync pod")
	}
}

func (ih *InformerHandler) deleteHandler(ctx context.Context, pod *corev1.Pod) {
	log := ih.c.Log.WithFields(logrus.Fields{
		"ns":  pod.Namespace,
		"pod": pod.Name,
	})
	if err := ih.c.Controller.DeletePod(ctx, pod); err != nil {
		log.WithError(err).Error("Failed to sync pod")
	}
}

func (ih *InformerHandler) Run(ctx context.Context) error {
	podInformer := ih.c.Factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{

		AddFunc: func(obj interface{}) {
			switch v := obj.(type) {
			case *corev1.Pod: // It can only be this type, so we just ignore anything else
				ih.addHandler(ctx, v)
			default:
				ih.c.Log.Errorf("BUG: k8s client-go returned type %T", v)
			}
		},

		UpdateFunc: func(old, new interface{}) {
			switch v := new.(type) {
			case *corev1.Pod:
				ih.addHandler(ctx, v)
			default:
				ih.c.Log.Errorf("BUG: k8s client-go returned type %T", v)
			}
		},

		DeleteFunc: func(obj interface{}) {
			switch v := obj.(type) {
			case *corev1.Pod:
				ih.deleteHandler(ctx, v)
			case cache.DeletedFinalStateUnknown:
				// This might be a stale object, but since we only
				// wanted the metadata, we just unwrap the type and
				// move on - Namespace and Name are immutable so they
				// are still correct.
				switch v2 := v.Obj.(type) {
				case *corev1.Pod:
					ih.deleteHandler(ctx, v2)
				default:
					ih.c.Log.Errorf("BUG: k8s client-go returned type %T", v)
				}
			default:
				ih.c.Log.Errorf("BUG: k8s client-go returned type %T", v)
			}
		},
	})

	ih.c.Factory.Start(ctx.Done())

	if ok := cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	ih.c.Log.Info("all pods synced")

	<-ctx.Done()
	return nil
}
