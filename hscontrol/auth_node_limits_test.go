package hscontrol

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// createTestAppWithNodeLimits returns a test app enforcing limits.
func createTestAppWithNodeLimits(t *testing.T, limits types.NodeLimitsConfig) *Headscale {
	t.Helper()

	app := createTestApp(t)
	app.cfg.Node.Limits = limits

	return app
}

// registerWithAuthKey registers a fresh machine with authKey and returns the response.
func registerWithAuthKey(t *testing.T, app *Headscale, authKey, hostname string) *tailcfg.RegisterResponse {
	t.Helper()

	return registerMachineWithAuthKey(t, app, authKey, hostname, key.NewMachine(), key.NewNode())
}

func registerMachineWithAuthKey(
	t *testing.T,
	app *Headscale,
	authKey, hostname string,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
) *tailcfg.RegisterResponse {
	t.Helper()

	resp, err := app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: authKey},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
		Expiry:   time.Now().Add(24 * time.Hour),
	}, machineKey.Public())
	require.NoError(t, err)
	require.NotNil(t, resp)

	return resp
}

func requireNodeLimitError(t *testing.T, resp *tailcfg.RegisterResponse) {
	t.Helper()

	assert.Contains(t, resp.Error, state.ErrUserNodeLimitReached.Error())
	assert.False(t, resp.MachineAuthorized)
	assert.Empty(t, resp.AuthURL)
}

func TestUserNodeLimitPreAuthKey(t *testing.T) {
	t.Parallel()

	app := createTestAppWithNodeLimits(t, types.NodeLimitsConfig{
		MaxNodesPerUser: 1,
		CountExpired:    true,
		CountEphemeral:  true,
	})

	user := app.state.CreateUserForTest("limited")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	resp := registerMachineWithAuthKey(t, app, pak.Key, "first", machineKey, nodeKey)
	require.Empty(t, resp.Error)
	require.True(t, resp.MachineAuthorized)

	requireNodeLimitError(t, registerWithAuthKey(t, app, pak.Key, "second"))
	assert.Equal(t, 1, app.state.ListNodesByUser(types.UserID(user.ID)).Len())

	// The node already counted against the limit may still re-register.
	resp = registerMachineWithAuthKey(t, app, pak.Key, "first", machineKey, nodeKey)
	assert.Empty(t, resp.Error)
	assert.True(t, resp.MachineAuthorized)
}

func TestUserNodeLimitExemptUsers(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		entry string
	}{
		{name: "by name", entry: "exempt"},
		{name: "by email", entry: "exempt@example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := createTestAppWithNodeLimits(t, types.NodeLimitsConfig{
				MaxNodesPerUser: 1,
				ExemptUsers:     []string{tt.entry},
				CountExpired:    true,
				CountEphemeral:  true,
			})

			user, _, err := app.state.CreateUser(types.User{
				Name:  "exempt",
				Email: "exempt@example.com",
			})
			require.NoError(t, err)

			pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			for i := range 3 {
				resp := registerWithAuthKey(t, app, pak.Key, fmt.Sprintf("node-%d", i))
				assert.Empty(t, resp.Error)
				assert.True(t, resp.MachineAuthorized)
			}
		})
	}
}

func TestUserNodeLimitIgnoresTaggedNodes(t *testing.T) {
	t.Parallel()

	app := createTestAppWithNodeLimits(t, types.NodeLimitsConfig{
		MaxNodesPerUser: 1,
		CountExpired:    true,
		CountEphemeral:  true,
	})

	user := app.state.CreateUserForTest("tag-owner")
	require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

	_, err := app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:server": ["tag-owner@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	userKey, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	taggedKey, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, []string{"tag:server"})
	require.NoError(t, err)

	require.Empty(t, registerWithAuthKey(t, app, userKey.Key, "personal").Error)

	for i := range 2 {
		resp := registerWithAuthKey(t, app, taggedKey.Key, fmt.Sprintf("server-%d", i))
		assert.Empty(t, resp.Error, "tagged nodes are not owned by the user")
		assert.True(t, resp.MachineAuthorized)
	}

	requireNodeLimitError(t, registerWithAuthKey(t, app, userKey.Key, "personal-2"))
}

func TestUserNodeLimitCountEphemeral(t *testing.T) {
	t.Parallel()

	app := createTestAppWithNodeLimits(t, types.NodeLimitsConfig{
		MaxNodesPerUser: 1,
		CountExpired:    true,
		CountEphemeral:  false,
	})

	user := app.state.CreateUserForTest("ephemeral")

	ephemeralKey, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)

	userKey, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	require.Empty(t, registerWithAuthKey(t, app, ephemeralKey.Key, "ephemeral-1").Error)
	require.Empty(t, registerWithAuthKey(t, app, ephemeralKey.Key, "ephemeral-2").Error)
	require.Empty(t, registerWithAuthKey(t, app, userKey.Key, "persistent").Error)

	requireNodeLimitError(t, registerWithAuthKey(t, app, userKey.Key, "persistent-2"))
}

func TestUserNodeLimitCountExpired(t *testing.T) {
	t.Parallel()

	for _, countExpired := range []bool{true, false} {
		t.Run(fmt.Sprintf("count_expired=%t", countExpired), func(t *testing.T) {
			t.Parallel()

			app := createTestAppWithNodeLimits(t, types.NodeLimitsConfig{
				MaxNodesPerUser: 1,
				CountExpired:    countExpired,
				CountEphemeral:  true,
			})

			user := app.state.CreateUserForTest("expired")
			pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			require.Empty(t, registerWithAuthKey(t, app, pak.Key, "old").Error)

			nodes := app.state.ListNodesByUser(types.UserID(user.ID))
			require.Equal(t, 1, nodes.Len())

			past := time.Now().Add(-time.Hour)
			_, _, err = app.state.SetNodeExpiry(nodes.At(0).ID(), &past)
			require.NoError(t, err)

			resp := registerWithAuthKey(t, app, pak.Key, "new")
			if countExpired {
				requireNodeLimitError(t, resp)
			} else {
				assert.Empty(t, resp.Error)
				assert.True(t, resp.MachineAuthorized)
			}
		})
	}
}

func TestUserNodeLimitEnforceOnReauth(t *testing.T) {
	t.Parallel()

	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce_on_reauth=%t", enforce), func(t *testing.T) {
			t.Parallel()

			app := createTestAppWithNodeLimits(t, types.NodeLimitsConfig{
				MaxNodesPerUser: 2,
				CountExpired:    true,
				CountEphemeral:  true,
				EnforceOnReauth: enforce,
			})

			user := app.state.CreateUserForTest("reauth")
			pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			machineKey := key.NewMachine()
			nodeKey := key.NewNode()

			require.Empty(t, registerMachineWithAuthKey(t, app, pak.Key, "first", machineKey, nodeKey).Error)
			require.Empty(t, registerWithAuthKey(t, app, pak.Key, "second").Error)

			// The operator lowers the limit below what the user already owns.
			app.cfg.Node.Limits.MaxNodesPerUser = 1

			resp := registerMachineWithAuthKey(t, app, pak.Key, "first", machineKey, nodeKey)
			if enforce {
				requireNodeLimitError(t, resp)
			} else {
				assert.Empty(t, resp.Error)
				assert.True(t, resp.MachineAuthorized)
			}
		})
	}
}

// The subtests share one app and run in order: the tagged subtest relies on
// the user already being at the limit.
func TestUserNodeLimitInteractive(t *testing.T) {
	app := createTestAppWithNodeLimits(t, types.NodeLimitsConfig{
		MaxNodesPerUser: 1,
		CountExpired:    true,
		CountEphemeral:  true,
	})

	user := app.state.CreateUserForTest("interactive")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)
	require.Empty(t, registerWithAuthKey(t, app, pak.Key, "existing").Error)

	t.Run("auth path refuses a new node", func(t *testing.T) {
		authID := types.MustAuthID()
		regEntry := types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "interactive-new",
		})
		app.state.SetAuthCacheEntry(authID, regEntry)

		_, _, err := app.state.HandleNodeFromAuthPath(authID, types.UserID(user.ID), nil, "webauth")
		require.ErrorIs(t, err, state.ErrUserNodeLimitReached)

		verdict := <-regEntry.WaitForAuth()
		require.ErrorIs(t, verdict.Err, state.ErrUserNodeLimitReached)
		assert.Equal(t, 1, app.state.ListNodesByUser(types.UserID(user.ID)).Len())
	})

	t.Run("auth path allows a tagged node", func(t *testing.T) {
		require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

		_, err := app.state.SetPolicy([]byte(`{
			"tagOwners": {"tag:server": ["interactive@"]},
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
		}`))
		require.NoError(t, err)

		authID := types.MustAuthID()
		app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "interactive-tagged",
			Hostinfo: &tailcfg.Hostinfo{
				Hostname:    "interactive-tagged",
				RequestTags: []string{"tag:server"},
			},
		}))

		node, _, err := app.state.HandleNodeFromAuthPath(authID, types.UserID(user.ID), nil, "webauth")
		require.NoError(t, err)
		assert.True(t, node.IsTagged())
	})

	// Without the limit check in waitForFollowup the client would be handed
	// a fresh AuthURL and loop through logins without seeing the reason.
	t.Run("followup returns the error to the client", func(t *testing.T) {
		machineKey := key.NewMachine()
		authID := types.MustAuthID()
		regEntry := types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: machineKey.Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "followup",
		})
		app.state.SetAuthCacheEntry(authID, regEntry)
		regEntry.FinishAuth(types.AuthVerdict{
			Err: fmt.Errorf("%w: test", state.ErrUserNodeLimitReached),
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := app.handleRegister(ctx, tailcfg.RegisterRequest{
			Followup: fmt.Sprintf("http://localhost:8080/register/%s", authID),
			NodeKey:  key.NewNode().Public(),
		}, machineKey.Public())
		require.NoError(t, err)
		require.NotNil(t, resp)
		requireNodeLimitError(t, resp)
	})
}
