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

func (ih *InformerHandler) Run(ctx context.Context) error {
	podInformer := ih.c.Factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{

		AddFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			log := ih.c.Log.WithFields(logrus.Fields{
				"ns":  pod.Namespace,
				"pod": pod.Name,
			})
			if err := ih.c.Controller.SyncPod(ctx, pod); err != nil {
				log.WithError(err).Error("Failed to sync pod")
			}
		},

		UpdateFunc: func(old, new interface{}) {
			oldPod := old.(*corev1.Pod)
			newPod := new.(*corev1.Pod)
			log := ih.c.Log.WithFields(logrus.Fields{
				"ns":  newPod.Namespace,
				"pod": newPod.Name,
			})
			if oldPod.ResourceVersion != newPod.ResourceVersion {
				if err := ih.c.Controller.SyncPod(ctx, newPod); err != nil {
					log.WithError(err).Error("Failed to sync pod")
				}
			}
		},

		DeleteFunc: func(obj interface{}) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				// This might be stale, but we're only going to use the name anyway
				obj = tombstone.Obj
			}
			pod := obj.(*corev1.Pod)
			log := ih.c.Log.WithFields(logrus.Fields{
				"ns":  pod.Namespace,
				"pod": pod.Name,
			})
			if err := ih.c.Controller.DeletePod(ctx, pod); err != nil {
				log.WithError(err).Error("Failed to sync pod")
			}
		},
	})

	ih.c.Factory.Start(ctx.Done())

	if ok := cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	<-ctx.Done()
	return nil
}
