// Code generated by mockery v2.51.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// MockReservationCentralSystemHandler is an autogenerated mock type for the CentralSystemHandler type
type MockReservationCentralSystemHandler struct {
	mock.Mock
}

type MockReservationCentralSystemHandler_Expecter struct {
	mock *mock.Mock
}

func (_m *MockReservationCentralSystemHandler) EXPECT() *MockReservationCentralSystemHandler_Expecter {
	return &MockReservationCentralSystemHandler_Expecter{mock: &_m.Mock}
}

// NewMockReservationCentralSystemHandler creates a new instance of MockReservationCentralSystemHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockReservationCentralSystemHandler(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockReservationCentralSystemHandler {
	mock := &MockReservationCentralSystemHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
