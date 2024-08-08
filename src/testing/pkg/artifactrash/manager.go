// Code generated by mockery v2.43.2. DO NOT EDIT.

package artifactrash

import (
	context "context"

	model "github.com/goharbor/harbor/src/pkg/artifactrash/model"
	mock "github.com/stretchr/testify/mock"
)

// Manager is an autogenerated mock type for the Manager type
type Manager struct {
	mock.Mock
}

// Create provides a mock function with given fields: ctx, artifactrsh
func (_m *Manager) Create(ctx context.Context, artifactrsh *model.ArtifactTrash) (int64, error) {
	ret := _m.Called(ctx, artifactrsh)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *model.ArtifactTrash) (int64, error)); ok {
		return rf(ctx, artifactrsh)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *model.ArtifactTrash) int64); ok {
		r0 = rf(ctx, artifactrsh)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *model.ArtifactTrash) error); ok {
		r1 = rf(ctx, artifactrsh)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: ctx, id
func (_m *Manager) Delete(ctx context.Context, id int64) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, int64) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Filter provides a mock function with given fields: ctx, timeWindow
func (_m *Manager) Filter(ctx context.Context, timeWindow int64) ([]model.ArtifactTrash, error) {
	ret := _m.Called(ctx, timeWindow)

	if len(ret) == 0 {
		panic("no return value specified for Filter")
	}

	var r0 []model.ArtifactTrash
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, int64) ([]model.ArtifactTrash, error)); ok {
		return rf(ctx, timeWindow)
	}
	if rf, ok := ret.Get(0).(func(context.Context, int64) []model.ArtifactTrash); ok {
		r0 = rf(ctx, timeWindow)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.ArtifactTrash)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, int64) error); ok {
		r1 = rf(ctx, timeWindow)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Flush provides a mock function with given fields: ctx, timeWindow
func (_m *Manager) Flush(ctx context.Context, timeWindow int64) error {
	ret := _m.Called(ctx, timeWindow)

	if len(ret) == 0 {
		panic("no return value specified for Flush")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, int64) error); ok {
		r0 = rf(ctx, timeWindow)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewManager creates a new instance of Manager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *Manager {
	mock := &Manager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
