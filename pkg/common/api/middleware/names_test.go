package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetricKey(t *testing.T) {
	assert.Equal(t, "one", metricKey("One"))
	assert.Equal(t, "one_two_three_four", metricKey("one,two,three,Four"))
	assert.Equal(t, "abc_def", metricKey("ABCDef"))
	assert.Equal(t, "v1", metricKey("v1"))
	assert.Equal(t, "abc_def", metricKey("AbcDEF"))
	assert.Equal(t, "one_two_three", metricKey("OneTWOThree"))
	assert.Equal(t, "one_two_three", metricKey("ONETwoTHREE"))
}

func TestMakeMetricName(t *testing.T) {
	for _, tt := range []struct {
		fullMethod string
		service    string
		metricKey  []string
	}{
		// server logger
		{fullMethod: "/spire.api.server.logger.v1.Logger/GetLogger", service: "Logger", metricKey: []string{"logger", "get_logger"}},
		{fullMethod: "/spire.api.server.logger.v1.Logger/SetLogLevel", service: "Logger", metricKey: []string{"logger", "set_log_level"}},
		{fullMethod: "/spire.api.server.logger.v1.Logger/ResetLogLevel", service: "Logger", metricKey: []string{"logger", "reset_log_level"}},
		// agent logger
		{fullMethod: "/spire.api.agent.logger.v1.Logger/GetLogger", service: "Logger", metricKey: []string{"logger", "get_logger"}},
		{fullMethod: "/spire.api.agent.logger.v1.Logger/SetLogLevel", service: "Logger", metricKey: []string{"logger", "set_log_level"}},
		{fullMethod: "/spire.api.agent.logger.v1.Logger/ResetLogLevel", service: "Logger", metricKey: []string{"logger", "reset_log_level"}},
		// server agent
		{fullMethod: "/spire.api.server.agent.v1.Agent/AttestAgent", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "attest_agent"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/BanAgent", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "ban_agent"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/CountAgents", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "count_agents"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/CreateJoinToken", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "create_join_token"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/DeleteAgent", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "delete_agent"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/GetAgent", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "get_agent"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/ListAgents", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "list_agents"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/PostStatus", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "post_status"}},
		{fullMethod: "/spire.api.server.agent.v1.Agent/RenewAgent", service: "agent.v1.Agent", metricKey: []string{"agent", "v1", "agent", "renew_agent"}},
		// server bundle
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/AppendBundle", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "append_bundle"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/BatchCreateFederatedBundle", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "batch_create_federated_bundle"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/BatchDeleteFederatedBundle", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "batch_delete_federated_bundle"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/BatchSetFederatedBundle", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "batch_set_federated_bundle"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/BatchUpdateFederatedBundle", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "batch_update_federated_bundle"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/CountBundles", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "count_bundles"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/GetBundle", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "get_bundle"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/GetFederatedBundle", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "get_federated_bundle"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/ListFederatedBundles", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "list_federated_bundles"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/PublishJWTAuthority", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "publish_jwt_authority"}},
		{fullMethod: "/spire.api.server.bundle.v1.Bundle/PublishWITAuthority", service: "bundle.v1.Bundle", metricKey: []string{"bundle", "v1", "bundle", "publish_wit_authority"}},
		// server debug
		{fullMethod: "/spire.api.server.debug.v1.Debug/GetInfo", service: "debug.v1.Debug", metricKey: []string{"debug", "v1", "debug", "get_info"}},
		// agent debug
		{fullMethod: "/spire.agent.debug.v1.Debug/GetInfo", service: "Debug", metricKey: []string{"debug", "get_info"}},
		// server entry
		{fullMethod: "/spire.api.server.entry.v1.Entry/BatchCreateEntry", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "batch_create_entry"}},
		{fullMethod: "/spire.api.server.entry.v1.Entry/BatchDeleteEntry", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "batch_delete_entry"}},
		{fullMethod: "/spire.api.server.entry.v1.Entry/BatchUpdateEntry", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "batch_update_entry"}},
		{fullMethod: "/spire.api.server.entry.v1.Entry/CountEntries", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "count_entries"}},
		{fullMethod: "/spire.api.server.entry.v1.Entry/GetAuthorizedEntries", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "get_authorized_entries"}},
		{fullMethod: "/spire.api.server.entry.v1.Entry/GetEntry", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "get_entry"}},
		{fullMethod: "/spire.api.server.entry.v1.Entry/ListEntries", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "list_entries"}},
		{fullMethod: "/spire.api.server.entry.v1.Entry/SyncAuthorizedEntries", service: "entry.v1.Entry", metricKey: []string{"entry", "v1", "entry", "sync_authorized_entries"}},
		// server localauthority
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/ActivateJWTAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "activate_jwt_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/ActivateWITAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "activate_wit_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/ActivateX509Authority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "activate_x509_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/GetJWTAuthorityState", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "get_jwt_authority_state"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/GetWITAuthorityState", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "get_wit_authority_state"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/GetX509AuthorityState", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "get_x509_authority_state"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/PrepareJWTAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "prepare_jwt_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/PrepareWITAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "prepare_wit_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/PrepareX509Authority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "prepare_x509_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/RevokeJWTAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "revoke_jwt_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/RevokeWITAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "revoke_wit_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/RevokeX509Authority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "revoke_x509_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/RevokeX509UpstreamAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "revoke_x509_upstream_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/TaintJWTAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "taint_jwt_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/TaintWITAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "taint_wit_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/TaintX509Authority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "taint_x509_authority"}},
		{fullMethod: "/spire.api.server.localauthority.v1.LocalAuthority/TaintX509UpstreamAuthority", service: "localauthority.v1.LocalAuthority", metricKey: []string{"localauthority", "v1", "local_authority", "taint_x509_upstream_authority"}},
		// server svid
		{fullMethod: "/spire.api.server.svid.v1.SVID/BatchNewWITSVID", service: "svid.v1.SVID", metricKey: []string{"svid", "v1", "svid", "batch_new_witsvid"}},
		{fullMethod: "/spire.api.server.svid.v1.SVID/BatchNewX509SVID", service: "svid.v1.SVID", metricKey: []string{"svid", "v1", "svid", "batch_new_x509svid"}},
		{fullMethod: "/spire.api.server.svid.v1.SVID/MintJWTSVID", service: "svid.v1.SVID", metricKey: []string{"svid", "v1", "svid", "mint_jwtsvid"}},
		{fullMethod: "/spire.api.server.svid.v1.SVID/MintWITSVID", service: "svid.v1.SVID", metricKey: []string{"svid", "v1", "svid", "mint_witsvid"}},
		{fullMethod: "/spire.api.server.svid.v1.SVID/MintX509SVID", service: "svid.v1.SVID", metricKey: []string{"svid", "v1", "svid", "mint_x509svid"}},
		{fullMethod: "/spire.api.server.svid.v1.SVID/NewDownstreamX509CA", service: "svid.v1.SVID", metricKey: []string{"svid", "v1", "svid", "new_downstream_x509ca"}},
		{fullMethod: "/spire.api.server.svid.v1.SVID/NewJWTSVID", service: "svid.v1.SVID", metricKey: []string{"svid", "v1", "svid", "new_jwtsvid"}},
		// server trustdomain
		{fullMethod: "/spire.api.server.trustdomain.v1.TrustDomain/BatchCreateFederationRelationship", service: "trustdomain.v1.TrustDomain", metricKey: []string{"trustdomain", "v1", "trust_domain", "batch_create_federation_relationship"}},
		{fullMethod: "/spire.api.server.trustdomain.v1.TrustDomain/BatchDeleteFederationRelationship", service: "trustdomain.v1.TrustDomain", metricKey: []string{"trustdomain", "v1", "trust_domain", "batch_delete_federation_relationship"}},
		{fullMethod: "/spire.api.server.trustdomain.v1.TrustDomain/BatchUpdateFederationRelationship", service: "trustdomain.v1.TrustDomain", metricKey: []string{"trustdomain", "v1", "trust_domain", "batch_update_federation_relationship"}},
		{fullMethod: "/spire.api.server.trustdomain.v1.TrustDomain/GetFederationRelationship", service: "trustdomain.v1.TrustDomain", metricKey: []string{"trustdomain", "v1", "trust_domain", "get_federation_relationship"}},
		{fullMethod: "/spire.api.server.trustdomain.v1.TrustDomain/ListFederationRelationships", service: "trustdomain.v1.TrustDomain", metricKey: []string{"trustdomain", "v1", "trust_domain", "list_federation_relationships"}},
		{fullMethod: "/spire.api.server.trustdomain.v1.TrustDomain/RefreshBundle", service: "trustdomain.v1.TrustDomain", metricKey: []string{"trustdomain", "v1", "trust_domain", "refresh_bundle"}},
		// agent delegatedidentity
		{fullMethod: "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/FetchJWTSVIDs", service: "DelegatedIdentity", metricKey: []string{"delegated_identity", "fetch_jwtsvi_ds"}},
		{fullMethod: "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToJWTBundles", service: "DelegatedIdentity", metricKey: []string{"delegated_identity", "subscribe_to_jwt_bundles"}},
		{fullMethod: "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509Bundles", service: "DelegatedIdentity", metricKey: []string{"delegated_identity", "subscribe_to_x509_bundles"}},
		{fullMethod: "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509SVIDs", service: "DelegatedIdentity", metricKey: []string{"delegated_identity", "subscribe_to_x509_svids"}},
		// workload api
		{fullMethod: "/SpiffeWorkloadAPI/FetchJWTBundles", service: "WorkloadAPI", metricKey: []string{"workload_api", "fetch_jwt_bundles"}},
		{fullMethod: "/SpiffeWorkloadAPI/FetchJWTSVID", service: "WorkloadAPI", metricKey: []string{"workload_api", "fetch_jwtsvid"}},
		{fullMethod: "/SpiffeWorkloadAPI/FetchWITBundles", service: "WorkloadAPI", metricKey: []string{"workload_api", "fetch_wit_bundles"}},
		{fullMethod: "/SpiffeWorkloadAPI/FetchWITSVID", service: "WorkloadAPI", metricKey: []string{"workload_api", "fetch_witsvid"}},
		{fullMethod: "/SpiffeWorkloadAPI/FetchX509Bundles", service: "WorkloadAPI", metricKey: []string{"workload_api", "fetch_x509_bundles"}},
		{fullMethod: "/SpiffeWorkloadAPI/FetchX509SVID", service: "WorkloadAPI", metricKey: []string{"workload_api", "fetch_x509svid"}},
		{fullMethod: "/SpiffeWorkloadAPI/ValidateJWTSVID", service: "WorkloadAPI", metricKey: []string{"workload_api", "validate_jwtsvid"}},
		// envoy sds v3
		{fullMethod: "/envoy.service.secret.v3.SecretDiscoveryService/DeltaSecrets", service: "SDS.v3", metricKey: []string{"sds", "v3", "delta_secrets"}},
		{fullMethod: "/envoy.service.secret.v3.SecretDiscoveryService/FetchSecrets", service: "SDS.v3", metricKey: []string{"sds", "v3", "fetch_secrets"}},
		{fullMethod: "/envoy.service.secret.v3.SecretDiscoveryService/StreamSecrets", service: "SDS.v3", metricKey: []string{"sds", "v3", "stream_secrets"}},
		// health
		{fullMethod: "/grpc.health.v1.Health/Check", service: "Health", metricKey: []string{"health", "check"}},
		{fullMethod: "/grpc.health.v1.Health/List", service: "Health", metricKey: []string{"health", "list"}},
		{fullMethod: "/grpc.health.v1.Health/Watch", service: "Health", metricKey: []string{"health", "watch"}},
		// reflection
		{fullMethod: "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", service: "grpc.reflection.v1.ServerReflection", metricKey: []string{"grpc", "reflection", "v1", "server_reflection", "server_reflection_info"}},
		{fullMethod: "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", service: "grpc.reflection.v1alpha.ServerReflection", metricKey: []string{"grpc", "reflection", "v1alpha", "server_reflection", "server_reflection_info"}},
	} {
		t.Run(tt.fullMethod, func(t *testing.T) {
			names := makeNames(tt.fullMethod)
			assert.Equal(t, tt.service, names.Service)
			assert.Equal(t, tt.metricKey, names.MetricKey)
		})
	}
}
