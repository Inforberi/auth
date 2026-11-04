package admin

import (
	"errors"

	"github.com/redis/go-redis/v9"

	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	projectdelivery "github.com/Inforberi/financial-intelligence/internal/auth/project/delivery"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func assembleProjectDelivery(cfg config.PlatformConfig, runtime *projectapp.Runtime, rdb *redis.Client) (*projectdelivery.ProjectDelivery, error) {
	if !cfg.Delivery.Enabled {
		return nil, nil
	}
	if runtime == nil {
		return nil, errors.New("project delivery requires project runtime")
	}
	c := cfg.Delivery
	return projectdelivery.NewProjectDelivery(projectdelivery.ProjectDeliveryConfig{Parallelism: c.Parallelism, PageSize: c.PageSize, Interval: c.Interval, SMTPAllowedTargets: c.Targets()}, projectbinding.ProjectSMTPDependencies{Registry: runtime.Registry, Reader: runtime.Reader, Redis: rdb})
}
