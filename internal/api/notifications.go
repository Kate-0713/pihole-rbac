// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

var errNoNotifications = errors.New("api: no notifications service configured")

// The handlers translate between the API's shapes and notifications.Service, which checks notifications.manage
// inside each change, applies the rules and writes the audit rows.

func channelJSON(c notifications.Channel) gen.Channel {
	out := gen.Channel{
		Id: c.ID, Kind: gen.ChannelKind(c.Kind), Name: c.Name, Enabled: c.Enabled, Events: c.Events,
		SecretSource: gen.ChannelSecretSource(c.SecretSource), CreatedAt: c.CreatedAt.UTC(),
	}
	if c.EnvName != "" {
		out.EnvName = ptr(c.EnvName)
	}
	if c.WebhookID != "" {
		out.WebhookId = ptr(c.WebhookID)
	}
	if c.Kind == notify.Matrix {
		out.Matrix = &gen.ChannelMatrix{Homeserver: c.Matrix.Homeserver, RoomId: c.Matrix.RoomID, AllowHttp: ptr(c.Matrix.AllowHTTP)}
	}
	if c.SecretVariable != "" {
		out.SecretVariable = ptr(c.SecretVariable)
	}
	if !c.SecretUpdatedAt.IsZero() {
		out.SecretUpdatedAt, out.SecretUpdatedBy = ptr(c.SecretUpdatedAt.UTC()), ptr(c.SecretUpdatedBy)
	}
	if c.SecretProblem != "" {
		out.SecretProblem = ptr(c.SecretProblem)
	}
	return out
}

func ptr[T any](v T) *T { return &v }

func channelInput(b *gen.ChannelInput) notifications.Input {
	in := notifications.Input{Kind: notify.Kind(b.Kind), Name: b.Name, Enabled: b.Enabled, Events: b.Events}
	if b.EnvName != nil {
		in.EnvName = *b.EnvName
	}
	if b.Matrix != nil {
		in.Matrix = notify.MatrixConfig{Homeserver: b.Matrix.Homeserver, RoomID: b.Matrix.RoomId}
		if b.Matrix.AllowHttp != nil {
			in.Matrix.AllowHTTP = *b.Matrix.AllowHttp
		}
	} else if in.Kind == notify.Matrix {
		in.Matrix = notify.MatrixConfig{} // refused by the service as a missing homeserver
	}
	if b.Secret != nil {
		v := secrets.NewValue([]byte(*b.Secret))
		in.Secret = &v
	}
	return in
}

func (s *Server) ListChannels(ctx context.Context, _ gen.ListChannelsRequestObject) (gen.ListChannelsResponseObject, error) {
	if s.Notifications == nil {
		return nil, errNoNotifications
	}
	list, err := s.Notifications.List(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ChannelList{Channels: make([]gen.Channel, 0, len(list)), CanStoreSecrets: s.Notifications.CanStoreSecrets()}
	for _, c := range list {
		out.Channels = append(out.Channels, channelJSON(c))
	}
	return gen.ListChannels200JSONResponse(out), nil
}

func (s *Server) GetChannel(ctx context.Context, req gen.GetChannelRequestObject) (gen.GetChannelResponseObject, error) {
	if s.Notifications == nil {
		return nil, errNoNotifications
	}
	c, err := s.Notifications.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetChannel200JSONResponse(channelJSON(c)), nil
}

func (s *Server) CreateChannel(ctx context.Context, req gen.CreateChannelRequestObject) (gen.CreateChannelResponseObject, error) {
	if s.Notifications == nil {
		return nil, errNoNotifications
	}
	c, err := s.Notifications.Create(ctx, actor(ctx), channelInput(req.Body))
	if err != nil {
		return nil, err
	}
	return gen.CreateChannel201JSONResponse(channelJSON(c)), nil
}

func (s *Server) UpdateChannel(ctx context.Context, req gen.UpdateChannelRequestObject) (gen.UpdateChannelResponseObject, error) {
	if s.Notifications == nil {
		return nil, errNoNotifications
	}
	c, err := s.Notifications.Update(ctx, actor(ctx), req.Id, channelInput(req.Body))
	if err != nil {
		return nil, err
	}
	return gen.UpdateChannel200JSONResponse(channelJSON(c)), nil
}

func (s *Server) DeleteChannel(ctx context.Context, req gen.DeleteChannelRequestObject) (gen.DeleteChannelResponseObject, error) {
	if s.Notifications == nil {
		return nil, errNoNotifications
	}
	if err := s.Notifications.Delete(ctx, actor(ctx), req.Id); err != nil {
		return nil, err
	}
	return gen.DeleteChannel204Response{}, nil
}

func (s *Server) SetChannelSecret(ctx context.Context, req gen.SetChannelSecretRequestObject) (gen.SetChannelSecretResponseObject, error) {
	if s.Notifications == nil {
		return nil, errNoNotifications
	}
	if req.Body.Secret == nil {
		return nil, invalid("secret", "Give the new secret.")
	}
	c, err := s.Notifications.SetSecret(ctx, actor(ctx), req.Id, secrets.NewValue([]byte(*req.Body.Secret)))
	if err != nil {
		return nil, err
	}
	return gen.SetChannelSecret200JSONResponse(channelJSON(c)), nil
}

func (s *Server) TestChannel(ctx context.Context, req gen.TestChannelRequestObject) (gen.TestChannelResponseObject, error) {
	if s.Notifications == nil {
		return nil, errNoNotifications
	}
	r, err := s.Notifications.Test(ctx, actor(ctx), req.Id)
	if err != nil {
		return nil, err
	}
	out := gen.ChannelTestResult{Ok: r.OK, Message: r.Message}
	if r.Status != 0 {
		out.Status = ptr(r.Status)
	}
	if r.Errcode != "" {
		out.Errcode = ptr(r.Errcode)
	}
	return gen.TestChannel200JSONResponse(out), nil
}

func (s *Server) ListNotificationEvents(context.Context, gen.ListNotificationEventsRequestObject) (gen.ListNotificationEventsResponseObject, error) {
	events := notifications.Events()
	out := gen.NotificationEventList{Events: make([]gen.NotificationEvent, 0, len(events))}
	for _, e := range events {
		out.Events = append(out.Events, gen.NotificationEvent{Name: e.Name, Group: e.Group, Description: e.Description})
	}
	return gen.ListNotificationEvents200JSONResponse(out), nil
}
