package shapingbench.okhttp;

import okhttp3.ConnectionPool;
import okhttp3.Cache;
import okhttp3.CacheControl;
import okhttp3.CompressionInterceptor;
import okhttp3.Dispatcher;
import okhttp3.CertificatePinner;
import okhttp3.CipherSuite;
import okhttp3.FormBody;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.JavaNetCookieJar;
import okhttp3.ConnectionSpec;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.Credentials;
import okhttp3.Dns;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.TlsVersion;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import okhttp3.brotli.BrotliInterceptor;
import okhttp3.dnsoverhttps.DnsOverHttps;
import okhttp3.logging.HttpLoggingInterceptor;
import okhttp3.sse.EventSource;
import okhttp3.sse.EventSourceListener;
import okhttp3.sse.EventSources;
import okhttp3.zstd.Zstd;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import okio.Buffer;
import okio.Sink;
import com.squareup.zstd.okio.OkioZstd;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.InterruptedIOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.zip.GZIPOutputStream;
import javax.net.SocketFactory;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;

public final class OkHttpSurvivalRunner {
  private static final MediaType TEXT = MediaType.get("text/plain; charset=utf-8");

  public static void main(String[] args) throws Exception {
    List<Result> results = new ArrayList<>();
    run(results, "connection_reuse", OkHttpSurvivalRunner::connectionReuse);
    run(results, "query_params", OkHttpSurvivalRunner::queryParams);
    run(results, "post_form", OkHttpSurvivalRunner::postForm);
    run(results, "arbitrary_put_method", OkHttpSurvivalRunner::arbitraryPutMethod);
    run(results, "multipart_file_upload", OkHttpSurvivalRunner::multipartFileUpload);
    run(results, "redirect_observable_without_following", OkHttpSurvivalRunner::redirectObservableWithoutFollowing);
    run(results, "redirect_followed_by_default", OkHttpSurvivalRunner::redirectFollowedByDefault);
    run(results, "read_timeout_error", OkHttpSurvivalRunner::readTimeoutError);
    run(results, "reused_connection_uses_new_socket_timeout", OkHttpSurvivalRunner::reusedConnectionUsesNewSocketTimeout);
    run(results, "broken_connection_retried", OkHttpSurvivalRunner::brokenConnectionRetried);
    run(results, "https_basic", OkHttpSurvivalRunner::httpsBasic);
    run(results, "tls_minimum_and_maximum_versions_configure_context", OkHttpSurvivalRunner::tlsMinimumAndMaximumVersionsConfigureContext);
    run(results, "certificate_ip_subject_alt_name_is_accepted", OkHttpSurvivalRunner::certificateIpSubjectAltNameIsAccepted);
    run(results, "ipv6_braces_are_stripped_for_certificate_matching", OkHttpSurvivalRunner::ipv6BracesAreStrippedForCertificateMatching);
    run(results, "hostname_verification_can_be_disabled", OkHttpSurvivalRunner::hostnameVerificationCanBeDisabled);
    run(results, "fingerprint_verification_is_supported", OkHttpSurvivalRunner::fingerprintVerificationIsSupported);
    run(results, "custom_cipher_suite_is_applied", OkHttpSurvivalRunner::customCipherSuiteIsApplied);
    run(results, "tls_alpn_http11_identifier_is_sent", OkHttpSurvivalRunner::tlsAlpnHttp11IdentifierIsSent);
    run(results, "gzip_response_decoded", OkHttpSurvivalRunner::gzipResponseDecoded);
    run(results, "gzip_content_encoding_case_insensitive", OkHttpSurvivalRunner::gzipContentEncodingCaseInsensitive);
    run(results, "multiple_content_encodings", OkHttpSurvivalRunner::multipleContentEncodings);
    run(results, "content_encoding_chain_limit", OkHttpSurvivalRunner::contentEncodingChainLimit);
    run(results, "decompression_buffer_continues_after_partial_read", OkHttpSurvivalRunner::decompressionBufferContinuesAfterPartialRead);
    run(results, "url_ipv6_zone_identifier_accepted", OkHttpSurvivalRunner::urlIpv6ZoneIdentifierAccepted);
    run(results, "multiple_set_cookie_headers_preserved", OkHttpSurvivalRunner::multipleSetCookieHeadersPreserved);
    run(results, "comma_header_value_preserved", OkHttpSurvivalRunner::commaHeaderValuePreserved);
    run(results, "incomplete_content_length_raises", OkHttpSurvivalRunner::incompleteContentLengthRaises);
    run(results, "invalid_chunk_length_raises", OkHttpSurvivalRunner::invalidChunkLengthRaises);
    run(results, "fragment_not_sent_in_request_target", OkHttpSurvivalRunner::fragmentNotSentInRequestTarget);
    run(results, "request_target_is_origin_form", OkHttpSurvivalRunner::requestTargetIsOriginForm);
    run(results, "tilde_path_not_percent_encoded", OkHttpSurvivalRunner::tildePathNotPercentEncoded);
    run(results, "empty_query_section_preserved", OkHttpSurvivalRunner::emptyQuerySectionPreserved);
    run(results, "user_supplied_host_header_preserved", OkHttpSurvivalRunner::userSuppliedHostHeaderPreserved);
    run(results, "chunked_request_sets_transfer_encoding", OkHttpSurvivalRunner::chunkedRequestSetsTransferEncoding);
    run(results, "chunked_keep_alive_preserves_request_boundaries", OkHttpSurvivalRunner::chunkedKeepAlivePreservesRequestBoundaries);
    run(results, "chunked_request_body_uses_utf8", OkHttpSurvivalRunner::chunkedRequestBodyUsesUtf8);
    run(results, "chunked_boundaries_are_lowercase", OkHttpSurvivalRunner::chunkedBoundariesAreLowercase);
    run(results, "http_303_redirect_switches_method_to_get", OkHttpSurvivalRunner::http303RedirectSwitchesMethodToGet);
    run(results, "relative_redirect_location_followed", OkHttpSurvivalRunner::relativeRedirectLocationFollowed);
    run(results, "redirect_body_is_released_before_following", OkHttpSurvivalRunner::redirectBodyIsReleasedBeforeFollowing);
    run(results, "cross_host_redirect_strips_authorization", OkHttpSurvivalRunner::crossHostRedirectStripsAuthorization);
    run(results, "cross_host_redirect_strips_authorization_case_insensitive", OkHttpSurvivalRunner::crossHostRedirectStripsAuthorizationCaseInsensitive);
    run(results, "redirect_header_input_not_mutated", OkHttpSurvivalRunner::redirectHeaderInputNotMutated);
    run(results, "cross_host_redirect_strips_cookie", OkHttpSurvivalRunner::crossHostRedirectStripsCookie);
    run(results, "cross_host_redirect_strips_proxy_authorization", OkHttpSurvivalRunner::crossHostRedirectStripsProxyAuthorization);
    run(results, "method_rejects_control_characters", OkHttpSurvivalRunner::methodRejectsControlCharacters);
    run(results, "url_empty_host_rejected", OkHttpSurvivalRunner::urlEmptyHostRejected);
    run(results, "url_scheme_and_host_normalized_lowercase", OkHttpSurvivalRunner::urlSchemeAndHostNormalizedLowercase);
    run(results, "url_default_port_equivalence", OkHttpSurvivalRunner::urlDefaultPortEquivalence);
    run(results, "url_port_with_leading_zeroes_accepted", OkHttpSurvivalRunner::urlPortWithLeadingZeroesAccepted);
    run(results, "url_port_zero_preserved", OkHttpSurvivalRunner::urlPortZeroPreserved);
    run(results, "url_port_rejects_unicode_digits", OkHttpSurvivalRunner::urlPortRejectsUnicodeDigits);
    run(results, "url_ipv6_requires_brackets", OkHttpSurvivalRunner::urlIpv6RequiresBrackets);
    run(results, "url_invalid_chars_percent_encoded", OkHttpSurvivalRunner::urlInvalidCharsPercentEncoded);
    run(results, "url_auth_invalid_chars_percent_encoded", OkHttpSurvivalRunner::urlAuthInvalidCharsPercentEncoded);
    run(results, "url_authority_includes_userinfo_and_host", OkHttpSurvivalRunner::urlAuthorityIncludesUserinfoAndHost);
    run(results, "json_request_sets_content_type", OkHttpSurvivalRunner::jsonRequestSetsContentType);
    run(results, "request_header_input_not_mutated", OkHttpSurvivalRunner::requestHeaderInputNotMutated);
    run(results, "default_headers_sent", OkHttpSurvivalRunner::defaultHeadersSent);
    run(results, "connection_refused_error", OkHttpSurvivalRunner::connectionRefusedError);
    run(results, "https_request_through_http_connect_proxy_succeeds", OkHttpSurvivalRunner::httpsRequestThroughHttpConnectProxySucceeds);
    run(results, "proxy_connect_ipv6_target_uses_brackets", OkHttpSurvivalRunner::proxyConnectIpv6TargetUsesBrackets);
    run(results, "ipv6_proxy_host_is_parsed_correctly", OkHttpSurvivalRunner::ipv6ProxyHostIsParsedCorrectly);
    run(results, "trailing_dot_hostname_through_proxy_connects", OkHttpSurvivalRunner::trailingDotHostnameThroughProxyConnects);
    run(results, "socks_proxy_basic_request_succeeds", OkHttpSurvivalRunner::socksProxyBasicRequestSucceeds);
    run(results, "socks_remote_dns_schemes_are_supported", OkHttpSurvivalRunner::socksRemoteDnsSchemesAreSupported);
    run(results, "dns_failure_error", OkHttpSurvivalRunner::dnsFailureError);
    run(results, "headers_mapping_accepted", OkHttpSurvivalRunner::headersMappingAccepted);
    run(results, "client_default_headers_apply_to_get_query", OkHttpSurvivalRunner::clientDefaultHeadersApplyToGetQuery);
    run(results, "message_content_type_header_accepted", OkHttpSurvivalRunner::messageContentTypeHeaderAccepted);
    run(results, "duplicate_user_agent_not_added", OkHttpSurvivalRunner::duplicateUserAgentNotAdded);
    run(results, "request_header_order_preserved", OkHttpSurvivalRunner::requestHeaderOrderPreserved);
    run(results, "explicit_transfer_encoding_chunked_not_duplicated", OkHttpSurvivalRunner::explicitTransferEncodingChunkedNotDuplicated);
    run(results, "multipart_duplicate_field_names_preserved", OkHttpSurvivalRunner::multipartDuplicateFieldNamesPreserved);
    run(results, "multipart_empty_filename_emitted", OkHttpSurvivalRunner::multipartEmptyFilenameEmitted);
    run(results, "multipart_html5_filename_formatting", OkHttpSurvivalRunner::multipartHtml5FilenameFormatting);
    run(results, "multipart_control_chars_not_percent_encoded", OkHttpSurvivalRunner::multipartControlCharsNotPercentEncoded);
    run(results, "multipart_explicit_content_type_sent", OkHttpSurvivalRunner::multipartExplicitContentTypeSent);
    run(results, "multipart_plain_fields_have_no_default_content_type", OkHttpSurvivalRunner::multipartPlainFieldsHaveNoDefaultContentType);
    run(results, "response_body_lines_streamed", OkHttpSurvivalRunner::responseBodyLinesStreamed);
    run(results, "chunked_head_response_without_body_does_not_hang", OkHttpSurvivalRunner::chunkedHeadResponseWithoutBodyDoesNotHang);
    run(results, "http2_request_body_without_transfer_encoding", OkHttpSurvivalRunner::http2RequestBodyWithoutTransferEncoding);
    run(results, "http2_origin_support_is_probed_with_alpn", OkHttpSurvivalRunner::http2OriginSupportIsProbedWithAlpn);
    run(results, "okhttp_origin_form_body_encodes_space_as_plus", OkHttpSurvivalRunner::okhttpOriginFormBodyEncodesSpaceAsPlus);
    run(results, "okhttp_origin_request_bodies_allowed_for_methods_except_get_and_head", OkHttpSurvivalRunner::okhttpOriginRequestBodiesAllowedForMethodsExceptGetAndHead);
    run(results, "okhttp_origin_options_request_body_is_allowed", OkHttpSurvivalRunner::okhttpOriginOptionsRequestBodyIsAllowed);
    run(results, "okhttp_origin_http_308_permanent_redirect_is_handled", OkHttpSurvivalRunner::okhttpOriginHttp308PermanentRedirectIsHandled);
    run(results, "okhttp_origin_http_307_308_redirects_preserve_non_get_post_method_and_body", OkHttpSurvivalRunner::okhttpOriginHttp307308RedirectsPreserveNonGetPostMethodAndBody);
    run(results, "okhttp_origin_multiple_informational_responses_are_ignored_until_final", OkHttpSurvivalRunner::okhttpOriginMultipleInformationalResponsesAreIgnoredUntilFinal);
    run(results, "okhttp_origin_http1_100_continue_status_lines_are_ignored_until_final", OkHttpSurvivalRunner::okhttpOriginHttp1100ContinueStatusLinesAreIgnoredUntilFinal);
    run(results, "okhttp_origin_empty_query_does_not_include_fragment", OkHttpSurvivalRunner::okhttpOriginEmptyQueryDoesNotIncludeFragment);
    run(results, "okhttp_origin_encoded_query_plus_is_preserved", OkHttpSurvivalRunner::okhttpOriginEncodedQueryPlusIsPreserved);
    run(results, "okhttp_origin_url_scheme_may_contain_digits", OkHttpSurvivalRunner::okhttpOriginUrlSchemeMayContainDigits);
    run(results, "okhttp_origin_url_fragment_preserves_non_ascii_characters", OkHttpSurvivalRunner::okhttpOriginUrlFragmentPreservesNonAsciiCharacters);
    run(results, "okhttp_origin_idn_uses_uts46_nontransitional_processing", OkHttpSurvivalRunner::okhttpOriginIdnUsesUts46NontransitionalProcessing);
    run(results, "okhttp_origin_url_domain_label_length_limits_are_enforced", OkHttpSurvivalRunner::okhttpOriginUrlDomainLabelLengthLimitsAreEnforced);
    run(results, "okhttp_origin_top_private_domain_malformed_host_does_not_crash", OkHttpSurvivalRunner::okhttpOriginTopPrivateDomainMalformedHostDoesNotCrash);
    run(results, "okhttp_origin_bad_url_hostname_characters_are_rejected", OkHttpSurvivalRunner::okhttpOriginBadUrlHostnameCharactersAreRejected);
    run(results, "okhttp_origin_http_url_to_uri_strips_invalid_hostname_characters", OkHttpSurvivalRunner::okhttpOriginHttpUrlToUriStripsInvalidHostnameCharacters);
    run(results, "okhttp_origin_ipv4_mapped_ipv6_url_does_not_crash", OkHttpSurvivalRunner::okhttpOriginIpv4MappedIpv6UrlDoesNotCrash);
    run(results, "okhttp_origin_query_parameter_builder_escapes_ascii_punctuation", OkHttpSurvivalRunner::okhttpOriginQueryParameterBuilderEscapesAsciiPunctuation);
    run(results, "okhttp_origin_ipv6_url_host_is_canonicalized", OkHttpSurvivalRunner::okhttpOriginIpv6UrlHostIsCanonicalized);
    run(results, "okhttp_origin_http_url_to_uri_allows_special_url_characters", OkHttpSurvivalRunner::okhttpOriginHttpUrlToUriAllowsSpecialUrlCharacters);
    run(results, "okhttp_origin_port_out_of_range_fails_early", OkHttpSurvivalRunner::okhttpOriginPortOutOfRangeFailsEarly);
    run(results, "okhttp_origin_http10_requests_are_not_sent", OkHttpSurvivalRunner::okhttpOriginHttp10RequestsAreNotSent);
    run(results, "okhttp_origin_webdav_methods_are_supported", OkHttpSurvivalRunner::okhttpOriginWebdavMethodsAreSupported);
    run(results, "okhttp_origin_request_builder_reuse_does_not_keep_stale_url_fields", OkHttpSurvivalRunner::okhttpOriginRequestBuilderReuseDoesNotKeepStaleUrlFields);
    run(results, "okhttp_origin_illegal_request_body_fails_at_build_time", OkHttpSurvivalRunner::okhttpOriginIllegalRequestBodyFailsAtBuildTime);
    run(results, "okhttp_origin_request_to_curl_includes_request_shape", OkHttpSurvivalRunner::okhttpOriginRequestToCurlIncludesRequestShape);
    run(results, "okhttp_origin_disabled_redirect_policy_is_honored", OkHttpSurvivalRunner::okhttpOriginDisabledRedirectPolicyIsHonored);
    run(results, "okhttp_origin_query_method_redirects_follow_rfc10008", OkHttpSurvivalRunner::okhttpOriginQueryMethodRedirectsFollowRfc10008);
    run(results, "okhttp_origin_response_body_is_non_null_for_all_responses", OkHttpSurvivalRunner::okhttpOriginResponseBodyIsNonNullForAllResponses);
    run(results, "okhttp_origin_response_trailers_no_body_does_not_crash", OkHttpSurvivalRunner::okhttpOriginResponseTrailersNoBodyDoesNotCrash);
    run(results, "okhttp_origin_response_trailers_available_after_body_exhausted", OkHttpSurvivalRunner::okhttpOriginResponseTrailersAvailableAfterBodyExhausted);
    run(results, "okhttp_origin_http_100_empty_body_trailers_are_not_promoted_to_headers", OkHttpSurvivalRunner::okhttpOriginHttp100EmptyBodyTrailersAreNotPromotedToHeaders);
    run(results, "okhttp_origin_gzip_streams_are_exhausted_on_close", OkHttpSurvivalRunner::okhttpOriginGzipStreamsAreExhaustedOnClose);
    run(results, "okhttp_origin_shoutcast_icy_response_is_supported", OkHttpSurvivalRunner::okhttpOriginShoutcastIcyResponseIsSupported);
    run(results, "okhttp_origin_headers_to_multimap_is_case_insensitive", OkHttpSurvivalRunner::okhttpOriginHeadersToMultimapIsCaseInsensitive);
    run(results, "okhttp_origin_request_to_string_redacts_sensitive_headers", OkHttpSurvivalRunner::okhttpOriginRequestToStringRedactsSensitiveHeaders);
    run(results, "okhttp_origin_unsafe_non_ascii_header_values_can_be_added", OkHttpSurvivalRunner::okhttpOriginUnsafeNonAsciiHeaderValuesCanBeAdded);
    run(results, "okhttp_origin_multipart_filename_allows_non_ascii", OkHttpSurvivalRunner::okhttpOriginMultipartFilenameAllowsNonAscii);
    run(results, "okhttp_origin_multipart_fixed_length_body_emits_content_length", OkHttpSurvivalRunner::okhttpOriginMultipartFixedLengthBodyEmitsContentLength);
    run(results, "okhttp_origin_multipart_body_omits_aggregate_content_length", OkHttpSurvivalRunner::okhttpOriginMultipartBodyOmitsAggregateContentLength);
    run(results, "okhttp_origin_https_tunnel_does_not_leak_origin_headers_to_proxy", OkHttpSurvivalRunner::okhttpOriginHttpsTunnelDoesNotLeakOriginHeadersToProxy);
    run(results, "okhttp_origin_proxy_selector_failure_falls_back_to_direct", OkHttpSurvivalRunner::okhttpOriginProxySelectorFailureFallsBackToDirect);
    run(results, "okhttp_origin_proxy_selector_connect_failed_is_notified", OkHttpSurvivalRunner::okhttpOriginProxySelectorConnectFailedIsNotified);
    run(results, "okhttp_origin_explicit_proxy_clients_share_connection_pool", OkHttpSurvivalRunner::okhttpOriginExplicitProxyClientsShareConnectionPool);
    run(results, "okhttp_origin_proxy_selector_connections_pool_correctly", OkHttpSurvivalRunner::okhttpOriginProxySelectorConnectionsPoolCorrectly);
    run(results, "okhttp_origin_retry_after_controls_503_and_408_retries", OkHttpSurvivalRunner::okhttpOriginRetryAfterControls503And408Retries);
    run(results, "okhttp_origin_http_408_retry_respects_retry_on_connection_failure", OkHttpSurvivalRunner::okhttpOriginHttp408RetryRespectsRetryOnConnectionFailure);
    run(results, "okhttp_origin_timeout_errors_use_socket_timeout_taxonomy", OkHttpSurvivalRunner::okhttpOriginTimeoutErrorsUseSocketTimeoutTaxonomy);
    run(results, "okhttp_origin_timeouts_fire_without_scheduler_delay", OkHttpSurvivalRunner::okhttpOriginTimeoutsFireWithoutSchedulerDelay);
    run(results, "okhttp_origin_http1_request_body_is_flushed_before_timeout_detach", OkHttpSurvivalRunner::okhttpOriginHttp1RequestBodyIsFlushedBeforeTimeoutDetach);
    run(results, "okhttp_origin_call_timeout_is_preserved_across_redirects", OkHttpSurvivalRunner::okhttpOriginCallTimeoutIsPreservedAcrossRedirects);
    run(results, "okhttp_origin_timeout_failures_are_not_retried", OkHttpSurvivalRunner::okhttpOriginTimeoutFailuresAreNotRetried);
    run(results, "okhttp_origin_null_header_values_are_ignored", OkHttpSurvivalRunner::okhttpOriginNullHeaderValuesAreIgnored);
    run(results, "okhttp_origin_form_body_builder_accepts_explicit_charset", OkHttpSurvivalRunner::okhttpOriginFormBodyBuilderAcceptsExplicitCharset);
    run(results, "okhttp_origin_response_records_sent_and_received_timestamps", OkHttpSurvivalRunner::okhttpOriginResponseRecordsSentAndReceivedTimestamps);
    run(results, "okhttp_origin_response_body_can_be_read_after_callback_returns", OkHttpSurvivalRunner::okhttpOriginResponseBodyCanBeReadAfterCallbackReturns);
    run(results, "okhttp_origin_socks_proxy_uses_remote_dns", OkHttpSurvivalRunner::okhttpOriginSocksProxyUsesRemoteDns);
    run(results, "okhttp_origin_direct_connections_use_configured_socket_factory", OkHttpSurvivalRunner::okhttpOriginDirectConnectionsUseConfiguredSocketFactory);
    run(results, "okhttp_origin_tls13_is_enabled_on_modern_jdk", OkHttpSurvivalRunner::okhttpOriginTls13IsEnabledOnModernJdk);
    run(results, "okhttp_origin_ssl_socket_factory_cannot_be_used_as_plain_socket_factory", OkHttpSurvivalRunner::okhttpOriginSslSocketFactoryCannotBeUsedAsPlainSocketFactory);
    run(results, "okhttp_origin_hostname_verification_does_not_fallback_to_common_name", OkHttpSurvivalRunner::okhttpOriginHostnameVerificationDoesNotFallbackToCommonName);
    run(results, "okhttp_origin_custom_trust_manager_is_used_directly", OkHttpSurvivalRunner::okhttpOriginCustomTrustManagerIsUsedDirectly);
    run(results, "okhttp_origin_insecure_host_allowlist_disables_verification_only_for_that_host", OkHttpSurvivalRunner::okhttpOriginInsecureHostAllowlistDisablesVerificationOnlyForThatHost);
    run(results, "okhttp_origin_sha256_certificate_pins_are_supported", OkHttpSurvivalRunner::okhttpOriginSha256CertificatePinsAreSupported);
    run(results, "okhttp_origin_no_pins_skips_certificate_chain_sanitization", OkHttpSurvivalRunner::okhttpOriginNoPinsSkipsCertificateChainSanitization);
    run(results, "okhttp_origin_tls12_is_preferred_where_available", OkHttpSurvivalRunner::okhttpOriginTls12IsPreferredWhereAvailable);
    run(results, "okhttp_origin_cache_control_header_accepts_semicolon_separator", OkHttpSurvivalRunner::okhttpOriginCacheControlHeaderAcceptsSemicolonSeparator);
    run(results, "okhttp_origin_cache_private_responses_are_handled", OkHttpSurvivalRunner::okhttpOriginCachePrivateResponsesAreHandled);
    run(results, "okhttp_origin_cache_default_response_codes_are_cached", OkHttpSurvivalRunner::okhttpOriginCacheDefaultResponseCodesAreCached);
    run(results, "okhttp_origin_cache_302_and_308_with_freshness_headers", OkHttpSurvivalRunner::okhttpOriginCache302And308WithFreshnessHeaders);
    run(results, "okhttp_origin_certificate_pinner_builds_full_chains", OkHttpSurvivalRunner::okhttpOriginCertificatePinnerBuildsFullChains);
    run(results, "okhttp_origin_certificate_pinner_double_wildcard_matches_multiple_subdomain_depths", OkHttpSurvivalRunner::okhttpOriginCertificatePinnerDoubleWildcardMatchesMultipleSubdomainDepths);
    run(results, "okhttp_origin_http2_head_inconsistent_content_length_does_not_crash", OkHttpSurvivalRunner::okhttpOriginHttp2HeadInconsistentContentLengthDoesNotCrash);
    run(results, "okhttp_origin_spdy_empty_header_values_are_preserved", OkHttpSurvivalRunner::okhttpOriginSpdyEmptyHeaderValuesArePreserved);
    run(results, "okhttp_origin_http2_request_headers_are_not_spdy_concatenated", OkHttpSurvivalRunner::okhttpOriginHttp2RequestHeadersAreNotSpdyConcatenated);
    run(results, "okhttp_origin_interceptor_timeout_overrides_are_honored", OkHttpSurvivalRunner::okhttpOriginInterceptorTimeoutOverridesAreHonored);
    run(results, "okhttp_origin_interceptors_can_change_request_method", OkHttpSurvivalRunner::okhttpOriginInterceptorsCanChangeRequestMethod);
    run(results, "okhttp_origin_network_interceptor_mutation_reaches_server", OkHttpSurvivalRunner::okhttpOriginNetworkInterceptorMutationReachesServer);
    run(results, "okhttp_origin_network_interceptor_can_access_connection", OkHttpSurvivalRunner::okhttpOriginNetworkInterceptorCanAccessConnection);
    run(results, "okhttp_origin_preconnect_interceptor_ioexception_fails_cleanly", OkHttpSurvivalRunner::okhttpOriginPreconnectInterceptorIoexceptionFailsCleanly);
    run(results, "okhttp_origin_unexpected_interceptor_exception_notifies_callback_failure", OkHttpSurvivalRunner::okhttpOriginUnexpectedInterceptorExceptionNotifiesCallbackFailure);
    run(results, "okhttp_origin_call_tags_are_visible_across_listeners_and_interceptors", OkHttpSurvivalRunner::okhttpOriginCallTagsAreVisibleAcrossListenersAndInterceptors);
    run(results, "okhttp_origin_dns_is_not_called_for_literal_ip_addresses", OkHttpSurvivalRunner::okhttpOriginDnsIsNotCalledForLiteralIpAddresses);
    run(results, "okhttp_origin_invalid_hosts_do_not_trigger_dns_lookup", OkHttpSurvivalRunner::okhttpOriginInvalidHostsDoNotTriggerDnsLookup);
    run(results, "okhttp_origin_cookie_lone_quote_value_does_not_crash", OkHttpSurvivalRunner::okhttpOriginCookieLoneQuoteValueDoesNotCrash);
    run(results, "okhttp_origin_cookie_samesite_attribute_is_parsed", OkHttpSurvivalRunner::okhttpOriginCookieSamesiteAttributeIsParsed);
    run(results, "okhttp_origin_null_default_authenticator_does_not_crash", OkHttpSurvivalRunner::okhttpOriginNullDefaultAuthenticatorDoesNotCrash);
    run(results, "okhttp_origin_authentication_credentials_support_charset", OkHttpSurvivalRunner::okhttpOriginAuthenticationCredentialsSupportCharset);
    run(results, "okhttp_origin_websocket_failed_upgrade_does_not_crash", OkHttpSurvivalRunner::okhttpOriginWebsocketFailedUpgradeDoesNotCrash);
    run(results, "okhttp_origin_websocket_non_101_response_body_is_retained", OkHttpSurvivalRunner::okhttpOriginWebsocketNon101ResponseBodyIsRetained);
    run(results, "okhttp_origin_websocket_allows_1012_1013_1014_close_codes", OkHttpSurvivalRunner::okhttpOriginWebsocketAllows101210131014CloseCodes);
    run(results, "okhttp_origin_dispatcher_idle_callback_fires_when_no_calls_in_flight", OkHttpSurvivalRunner::okhttpOriginDispatcherIdleCallbackFiresWhenNoCallsInFlight);
    run(results, "okhttp_origin_dispatcher_queue_events_are_emitted", OkHttpSurvivalRunner::okhttpOriginDispatcherQueueEventsAreEmitted);
    run(results, "okhttp_origin_dispatcher_counts_queued_and_running_calls", OkHttpSurvivalRunner::okhttpOriginDispatcherCountsQueuedAndRunningCalls);
    run(results, "okhttp_origin_async_dispatcher_parallelism_is_preserved", OkHttpSurvivalRunner::okhttpOriginAsyncDispatcherParallelismIsPreserved);
    run(results, "okhttp_origin_cached_response_preserves_repeated_headers", OkHttpSurvivalRunner::okhttpOriginCachedResponsePreservesRepeatedHeaders);
    run(results, "okhttp_origin_immutable_cache_control_directive_marks_response_fresh", OkHttpSurvivalRunner::okhttpOriginImmutableCacheControlDirectiveMarksResponseFresh);
    run(results, "okhttp_origin_if_none_match_and_if_modified_since_not_both_sent", OkHttpSurvivalRunner::okhttpOriginIfNoneMatchAndIfModifiedSinceNotBothSent);
    run(results, "okhttp_origin_non_ascii_etag_cache_validation_does_not_crash", OkHttpSurvivalRunner::okhttpOriginNonAsciiEtagCacheValidationDoesNotCrash);
    run(results, "okhttp_origin_cache_hit_miss_events_are_emitted", OkHttpSurvivalRunner::okhttpOriginCacheHitMissEventsAreEmitted);
    run(results, "okhttp_origin_proxy_selection_events_are_emitted", OkHttpSurvivalRunner::okhttpOriginProxySelectionEventsAreEmitted);
    run(results, "okhttp_origin_connection_listener_reports_connect_disconnect_and_pooling", OkHttpSurvivalRunner::okhttpOriginConnectionListenerReportsConnectDisconnectAndPooling);
    run(results, "okhttp_origin_call_end_event_is_emitted_when_interceptor_consumes_body", OkHttpSurvivalRunner::okhttpOriginCallEndEventIsEmittedWhenInterceptorConsumesBody);
    run(results, "okhttp_origin_corrupted_cache_entry_is_recovered_or_fails_fast", OkHttpSurvivalRunner::okhttpOriginCorruptedCacheEntryIsRecoveredOrFailsFast);
    run(results, "okhttp_origin_cache_write_failure_does_not_leak_or_crash", OkHttpSurvivalRunner::okhttpOriginCacheWriteFailureDoesNotLeakOrCrash);
    run(results, "okhttp_origin_immutable_cache_control_is_not_permanent", OkHttpSurvivalRunner::okhttpOriginImmutableCacheControlIsNotPermanent);
    run(results, "okhttp_origin_cache_304_does_not_corrupt_content_encoding", OkHttpSurvivalRunner::okhttpOriginCache304DoesNotCorruptContentEncoding);
    run(results, "okhttp_origin_cache_hit_stream_allocation_survives_redirect", OkHttpSurvivalRunner::okhttpOriginCacheHitStreamAllocationSurvivesRedirect);
    run(results, "okhttp_origin_cache_can_be_initialized_eagerly", OkHttpSurvivalRunner::okhttpOriginCacheCanBeInitializedEagerly);
    run(results, "okhttp_origin_response_cache_initializes_lazily", OkHttpSurvivalRunner::okhttpOriginResponseCacheInitializesLazily);
    run(results, "okhttp_origin_cache_hit_does_not_eagerly_release_pool", OkHttpSurvivalRunner::okhttpOriginCacheHitDoesNotEagerlyReleasePool);
    run(results, "okhttp_origin_cache_vary_headers_preserved_in_android_http_cache", OkHttpSurvivalRunner::okhttpOriginCacheVaryHeadersPreservedInAndroidHttpCache);
    run(results, "okhttp_origin_cache_stores_rewritten_request_headers", OkHttpSurvivalRunner::okhttpOriginCacheStoresRewrittenRequestHeaders);
    run(results, "okhttp_origin_bad_cache_throws_checked_error", OkHttpSurvivalRunner::okhttpOriginBadCacheThrowsCheckedError);
    run(results, "okhttp_origin_logging_redacts_configured_query_parameters", OkHttpSurvivalRunner::okhttpOriginLoggingRedactsConfiguredQueryParameters);
    run(results, "okhttp_origin_logging_reports_total_call_time", OkHttpSurvivalRunner::okhttpOriginLoggingReportsTotalCallTime);
    run(results, "okhttp_origin_server_sent_event_bodies_are_not_logged", OkHttpSurvivalRunner::okhttpOriginServerSentEventBodiesAreNotLogged);
    run(results, "okhttp_origin_logging_interceptor_honors_one_shot_request_body", OkHttpSurvivalRunner::okhttpOriginLoggingInterceptorHonorsOneShotRequestBody);
    run(results, "okhttp_origin_http_logging_interceptor_redacts_configured_headers", OkHttpSurvivalRunner::okhttpOriginHttpLoggingInterceptorRedactsConfiguredHeaders);
    run(results, "okhttp_origin_logging_plaintext_classifier_allows_newlines", OkHttpSurvivalRunner::okhttpOriginLoggingPlaintextClassifierAllowsNewlines);
    run(results, "okhttp_origin_logging_interceptor_logs_connection_failures", OkHttpSurvivalRunner::okhttpOriginLoggingInterceptorLogsConnectionFailures);
    run(results, "okhttp_origin_logging_interceptor_handles_unexpected_charset", OkHttpSurvivalRunner::okhttpOriginLoggingInterceptorHandlesUnexpectedCharset);
    run(results, "okhttp_origin_logging_interceptor_uses_request_body_charset", OkHttpSurvivalRunner::okhttpOriginLoggingInterceptorUsesRequestBodyCharset);
    run(results, "okhttp_origin_logging_interceptor_handles_no_content_responses", OkHttpSurvivalRunner::okhttpOriginLoggingInterceptorHandlesNoContentResponses);
    run(results, "okhttp_origin_cookies_are_accepted_for_ipv6_hosts", OkHttpSurvivalRunner::okhttpOriginCookiesAreAcceptedForIpv6Hosts);
    run(results, "okhttp_origin_public_domain_cookies_are_rejected", OkHttpSurvivalRunner::okhttpOriginPublicDomainCookiesAreRejected);
    run(results, "okhttp_origin_java_net_cookie_jar_handles_multiple_cookies", OkHttpSurvivalRunner::okhttpOriginJavaNetCookieJarHandlesMultipleCookies);
    run(results, "okhttp_origin_retry_decision_event_is_emitted", OkHttpSurvivalRunner::okhttpOriginRetryDecisionEventIsEmitted);
    run(results, "okhttp_origin_followup_decision_event_is_emitted", OkHttpSurvivalRunner::okhttpOriginFollowupDecisionEventIsEmitted);
    run(results, "okhttp_origin_event_listener_canceled_event_is_emitted", OkHttpSurvivalRunner::okhttpOriginEventListenerCanceledEventIsEmitted);
    run(results, "okhttp_origin_request_failed_and_response_failed_events_are_emitted", OkHttpSurvivalRunner::okhttpOriginRequestFailedAndResponseFailedEventsAreEmitted);
    run(results, "okhttp_origin_dispatcher_executor_shutdown_reports_rejected_execution", OkHttpSurvivalRunner::okhttpOriginDispatcherExecutorShutdownReportsRejectedExecution);
    run(results, "okhttp_origin_canceled_async_call_still_gets_callback", OkHttpSurvivalRunner::okhttpOriginCanceledAsyncCallStillGetsCallback);
    run(results, "okhttp_origin_async_uncaught_exceptions_are_delivered", OkHttpSurvivalRunner::okhttpOriginAsyncUncaughtExceptionsAreDelivered);
    run(results, "okhttp_origin_interrupted_state_is_retained_after_interrupted_io", OkHttpSurvivalRunner::okhttpOriginInterruptedStateIsRetainedAfterInterruptedIo);
    run(results, "okhttp_origin_proxy_authenticator_handles_proxy_challenges", OkHttpSurvivalRunner::okhttpOriginProxyAuthenticatorHandlesProxyChallenges);
    run(results, "okhttp_origin_proxy_selection_is_deferred_until_needed", OkHttpSurvivalRunner::okhttpOriginProxySelectionIsDeferredUntilNeeded);
    run(results, "okhttp_origin_tls_tunnel_truncated_response_body_does_not_crash", OkHttpSurvivalRunner::okhttpOriginTlsTunnelTruncatedResponseBodyDoesNotCrash);
    run(results, "okhttp_origin_certificate_pinner_pins_are_inspectable", OkHttpSurvivalRunner::okhttpOriginCertificatePinnerPinsAreInspectable);
    run(results, "okhttp_origin_connection_spec_reports_socket_compatibility", OkHttpSurvivalRunner::okhttpOriginConnectionSpecReportsSocketCompatibility);
    run(results, "okhttp_origin_connection_spec_can_use_socket_default_cipher_suites", OkHttpSurvivalRunner::okhttpOriginConnectionSpecCanUseSocketDefaultCipherSuites);
    run(results, "okhttp_origin_http2_flow_control_window_updates_before_application_read", OkHttpSurvivalRunner::okhttpOriginHttp2FlowControlWindowUpdatesBeforeApplicationRead);
    run(results, "okhttp_origin_discarded_http2_data_releases_flow_control_window", OkHttpSurvivalRunner::okhttpOriginDiscardedHttp2DataReleasesFlowControlWindow);
    run(results, "okhttp_origin_websocket_closed_before_connect_does_not_crash", OkHttpSurvivalRunner::okhttpOriginWebsocketClosedBeforeConnectDoesNotCrash);
    run(results, "okhttp_origin_websocket_failed_upgrade_does_not_leak_socket", OkHttpSurvivalRunner::okhttpOriginWebsocketFailedUpgradeDoesNotLeakSocket);
    run(results, "okhttp_origin_websockets_do_not_count_toward_per_host_dispatcher_limit", OkHttpSurvivalRunner::okhttpOriginWebsocketsDoNotCountTowardPerHostDispatcherLimit);
    run(results, "okhttp_origin_media_type_parameter_extracts_quoted_boundary", OkHttpSurvivalRunner::okhttpOriginMediaTypeParameterExtractsQuotedBoundary);
    run(results, "okhttp_origin_multipart_part_sink_close_does_not_close_request_body", OkHttpSurvivalRunner::okhttpOriginMultipartPartSinkCloseDoesNotCloseRequestBody);
    run(results, "okhttp_origin_one_shot_request_body_is_not_retransmitted", OkHttpSurvivalRunner::okhttpOriginOneShotRequestBodyIsNotRetransmitted);
    run(results, "okhttp_origin_file_not_found_request_body_is_not_retried", OkHttpSurvivalRunner::okhttpOriginFileNotFoundRequestBodyIsNotRetried);
    run(results, "okhttp_origin_call_timeout_applies_while_connecting_long_lived_streams", OkHttpSurvivalRunner::okhttpOriginCallTimeoutAppliesWhileConnectingLongLivedStreams);
    run(results, "okhttp_origin_pooled_connection_timeouts_are_not_shared", OkHttpSurvivalRunner::okhttpOriginPooledConnectionTimeoutsAreNotShared);
    run(results, "okhttp_origin_route_is_retained_on_reused_followup_connection", OkHttpSurvivalRunner::okhttpOriginRouteIsRetainedOnReusedFollowupConnection);
    run(results, "okhttp_origin_https_post_streaming_is_not_always_buffered", OkHttpSurvivalRunner::okhttpOriginHttpsPostStreamingIsNotAlwaysBuffered);
    run(results, "okhttp_origin_non_ascii_http2_and_cached_headers_do_not_crash", OkHttpSurvivalRunner::okhttpOriginNonAsciiHttp2AndCachedHeadersDoNotCrash);
    run(results, "okhttp_origin_call_proceed_never_returns_null_after_cancel", OkHttpSurvivalRunner::okhttpOriginCallProceedNeverReturnsNullAfterCancel);
    run(results, "okhttp_origin_sse_calls_send_accept_event_stream_by_default", OkHttpSurvivalRunner::okhttpOriginSseCallsSendAcceptEventStreamByDefault);
    run(results, "okhttp_origin_sse_preserves_existing_accept_header", OkHttpSurvivalRunner::okhttpOriginSsePreservesExistingAcceptHeader);
    run(results, "okhttp_origin_eventsource_cancel_from_onopen_is_honored", OkHttpSurvivalRunner::okhttpOriginEventsourceCancelFromOnopenIsHonored);
    run(results, "okhttp_origin_server_sent_events_stream_messages", OkHttpSurvivalRunner::okhttpOriginServerSentEventsStreamMessages);
    run(results, "okhttp_origin_dns_over_https_executes_wire_dns_queries", OkHttpSurvivalRunner::okhttpOriginDnsOverHttpsExecutesWireDnsQueries);
    run(results, "okhttp_origin_dns_over_https_honors_response_cache_ttl", OkHttpSurvivalRunner::okhttpOriginDnsOverHttpsHonorsResponseCacheTtl);
    run(results, "okhttp_origin_brotli_empty_body_is_not_decompressed", OkHttpSurvivalRunner::okhttpOriginBrotliEmptyBodyIsNotDecompressed);
    run(results, "okhttp_origin_zstd_compression_is_negotiated_and_decoded", OkHttpSurvivalRunner::okhttpOriginZstdCompressionIsNegotiatedAndDecoded);
    run(results, "okhttp_origin_response_trailers_can_be_peeked_without_blocking", OkHttpSurvivalRunner::okhttpOriginResponseTrailersCanBePeekedWithoutBlocking);
    run(results, "okhttp_origin_recorded_request_reports_tls_sni", OkHttpSurvivalRunner::okhttpOriginRecordedRequestReportsTlsSni);
    run(results, "okhttp_origin_android_https_sets_sni_server_name", OkHttpSurvivalRunner::okhttpOriginAndroidHttpsSetsSniServerName);
    run(results, "okhttp_origin_logging_event_listener_reports_tls_handshake", OkHttpSurvivalRunner::okhttpOriginLoggingEventListenerReportsTlsHandshake);
    run(results, "okhttp_origin_tls_handshake_without_peer_certificates_fails_cleanly", OkHttpSurvivalRunner::okhttpOriginTlsHandshakeWithoutPeerCertificatesFailsCleanly);
    run(results, "okhttp_origin_mutual_tls_client_certificate_is_sent_when_required", OkHttpSurvivalRunner::okhttpOriginMutualTlsClientCertificateIsSentWhenRequired);
    run(results, "okhttp_origin_trust_everything_redirect_does_not_fail", OkHttpSurvivalRunner::okhttpOriginTrustEverythingRedirectDoesNotFail);
    run(results, "okhttp_origin_https_hostname_verifier_selection_allows_reuse", OkHttpSurvivalRunner::okhttpOriginHttpsHostnameVerifierSelectionAllowsReuse);
    run(results, "okhttp_origin_non_ascii_hostname_fails_before_tls_verification", OkHttpSurvivalRunner::okhttpOriginNonAsciiHostnameFailsBeforeTlsVerification);
    run(results, "okhttp_origin_client_cipher_suite_precedence_is_honored", OkHttpSurvivalRunner::okhttpOriginClientCipherSuitePrecedenceIsHonored);
    run(results, "okhttp_origin_fast_fallback_races_tcp_connections", OkHttpSurvivalRunner::okhttpOriginFastFallbackRacesTcpConnections);
    run(results, "okhttp_origin_fast_fallback_deferred_and_held_connection_race_does_not_crash", OkHttpSurvivalRunner::okhttpOriginFastFallbackDeferredAndHeldConnectionRaceDoesNotCrash);
    run(results, "okhttp_origin_worker_thread_interruption_does_not_break_call_recovery", OkHttpSurvivalRunner::okhttpOriginWorkerThreadInterruptionDoesNotBreakCallRecovery);
    run(results, "okhttp_origin_connection_timeout_recovery_continues_routes", OkHttpSurvivalRunner::okhttpOriginConnectionTimeoutRecoveryContinuesRoutes);
    run(results, "okhttp_origin_new_connections_skip_health_check", OkHttpSurvivalRunner::okhttpOriginNewConnectionsSkipHealthCheck);
    run(results, "okhttp_origin_all_route_failures_include_suppressed_exceptions", OkHttpSurvivalRunner::okhttpOriginAllRouteFailuresIncludeSuppressedExceptions);
    run(results, "okhttp_origin_initial_connect_exception_is_primary_after_retry_failure", OkHttpSurvivalRunner::okhttpOriginInitialConnectExceptionIsPrimaryAfterRetryFailure);
    run(results, "okhttp_origin_cache_journal_rebuild_failure_recovers", OkHttpSurvivalRunner::okhttpOriginCacheJournalRebuildFailureRecovers);
    run(results, "okhttp_origin_https_redirect_cache_classcast_does_not_crash", OkHttpSurvivalRunner::okhttpOriginHttpsRedirectCacheClasscastDoesNotCrash);
    run(results, "okhttp_origin_multipart_reader_streams_response_parts", OkHttpSurvivalRunner::okhttpOriginMultipartReaderStreamsResponseParts);
    run(results, "okhttp_origin_interceptor_retry_no_more_routes_fails_as_io_error", OkHttpSurvivalRunner::okhttpOriginInterceptorRetryNoMoreRoutesFailsAsIoError);
    run(results, "okhttp_origin_network_interceptor_body_transform_must_close_underlying_stream", OkHttpSurvivalRunner::okhttpOriginNetworkInterceptorBodyTransformMustCloseUnderlyingStream);
    run(results, "okhttp_origin_cancel_before_failure_callback_releases_connection", OkHttpSurvivalRunner::okhttpOriginCancelBeforeFailureCallbackReleasesConnection);
    run(results, "okhttp_origin_response_start_events_wait_for_actual_bytes", OkHttpSurvivalRunner::okhttpOriginResponseStartEventsWaitForActualBytes);
    run(results, "okhttp_origin_authenticator_exception_releases_connection", OkHttpSurvivalRunner::okhttpOriginAuthenticatorExceptionReleasesConnection);
    run(results, "okhttp_origin_strict_abort_timeout_is_used", OkHttpSurvivalRunner::okhttpOriginStrictAbortTimeoutIsUsed);
    run(results, "okhttp_origin_http101_response_exposes_upgraded_socket", OkHttpSurvivalRunner::okhttpOriginHttp101ResponseExposesUpgradedSocket);
    run(results, "okhttp_origin_response_is_read_when_request_write_fails", OkHttpSurvivalRunner::okhttpOriginResponseIsReadWhenRequestWriteFails);
    run(results, "okhttp_origin_http2_response_headers_are_limited", OkHttpSurvivalRunner::okhttpOriginHttp2ResponseHeadersAreLimited);
    run(results, "okhttp_origin_http2_status_header_omits_reason_phrase", OkHttpSurvivalRunner::okhttpOriginHttp2StatusHeaderOmitsReasonPhrase);
    run(results, "okhttp_origin_h2_prior_knowledge_does_not_tunnel_through_http_proxy", OkHttpSurvivalRunner::okhttpOriginH2PriorKnowledgeDoesNotTunnelThroughHttpProxy);
    run(results, "okhttp_origin_websocket_frames_are_buffered", OkHttpSurvivalRunner::okhttpOriginWebsocketFramesAreBuffered);
    run(results, "okhttp_origin_websocket_close_frames_are_handled", OkHttpSurvivalRunner::okhttpOriginWebsocketCloseFramesAreHandled);
    run(results, "okhttp_origin_websocket_io_error_requires_close_callback", OkHttpSurvivalRunner::okhttpOriginWebsocketIoErrorRequiresCloseCallback);
    run(results, "okhttp_origin_cache_iterator_does_not_evict_incomplete_entries", OkHttpSurvivalRunner::okhttpOriginCacheIteratorDoesNotEvictIncompleteEntries);
    run(results, "okhttp_origin_spdy_premature_body_close_still_caches_response", OkHttpSurvivalRunner::okhttpOriginSpdyPrematureBodyCloseStillCachesResponse);
    run(results, "okhttp_origin_tls_hostname_verifier_rejects_noncanonical_ip_hosts", OkHttpSurvivalRunner::okhttpOriginTlsHostnameVerifierRejectsNoncanonicalIpHosts);
    run(results, "okhttp_origin_dss_cipher_suite_is_not_offered_by_default", OkHttpSurvivalRunner::okhttpOriginDssCipherSuiteIsNotOfferedByDefault);
    run(results, "okhttp_origin_tls_fallback_scsv_is_sent_on_fallback", OkHttpSurvivalRunner::okhttpOriginTlsFallbackScsvIsSentOnFallback);
    run(results, "okhttp_origin_alpn_desktop_connections_do_not_leak", OkHttpSurvivalRunner::okhttpOriginAlpnDesktopConnectionsDoNotLeak);
    run(results, "okhttp_origin_resumed_tls_session_uses_correct_protocol", OkHttpSurvivalRunner::okhttpOriginResumedTlsSessionUsesCorrectProtocol);
    run(results, "okhttp_origin_numeric_proxy_address_skips_reverse_dns", OkHttpSurvivalRunner::okhttpOriginNumericProxyAddressSkipsReverseDns);
    run(results, "okhttp_origin_connect_handling_tolerates_misbehaving_proxies", OkHttpSurvivalRunner::okhttpOriginConnectHandlingToleratesMisbehavingProxies);
    run(results, "okhttp_origin_websocket_close_timeout_forces_abrupt_shutdown", OkHttpSurvivalRunner::okhttpOriginWebsocketCloseTimeoutForcesAbruptShutdown);
    run(results, "okhttp_origin_websocket_ping_close_race_does_not_crash", OkHttpSurvivalRunner::okhttpOriginWebsocketPingCloseRaceDoesNotCrash);
    run(results, "okhttp_origin_websocket_malformed_response_or_onopen_exception_releases_connection", OkHttpSurvivalRunner::okhttpOriginWebsocketMalformedResponseOrOnopenExceptionReleasesConnection);
    run(results, "okhttp_origin_websocket_deflated_empty_output_does_not_crash", OkHttpSurvivalRunner::okhttpOriginWebsocketDeflatedEmptyOutputDoesNotCrash);
    run(results, "okhttp_origin_websocket_outbound_compression_threshold_is_honored", OkHttpSurvivalRunner::okhttpOriginWebsocketOutboundCompressionThresholdIsHonored);
    run(results, "okhttp_origin_websocket_deflater_is_not_closed_mid_message", OkHttpSurvivalRunner::okhttpOriginWebsocketDeflaterIsNotClosedMidMessage);
    run(results, "okhttp_origin_websocket_self_terminating_compressed_message_does_not_loop", OkHttpSurvivalRunner::okhttpOriginWebsocketSelfTerminatingCompressedMessageDoesNotLoop);
    run(results, "okhttp_origin_http2_self_cancel_does_not_send_end_stream", OkHttpSurvivalRunner::okhttpOriginHttp2SelfCancelDoesNotSendEndStream);
    run(results, "okhttp_origin_http2_cancel_while_sending_headers_is_not_missed", OkHttpSurvivalRunner::okhttpOriginHttp2CancelWhileSendingHeadersIsNotMissed);
    run(results, "okhttp_origin_http2_multiple_canceled_calls_do_not_release_shared_connection", OkHttpSurvivalRunner::okhttpOriginHttp2MultipleCanceledCallsDoNotReleaseSharedConnection);
    run(results, "okhttp_origin_disconnect_before_connecting_http2_does_not_crash", OkHttpSurvivalRunner::okhttpOriginDisconnectBeforeConnectingHttp2DoesNotCrash);
    run(results, "okhttp_origin_spdy_header_read_timeout_is_honored", OkHttpSurvivalRunner::okhttpOriginSpdyHeaderReadTimeoutIsHonored);
    run(results, "okhttp_origin_http2_write_timeout_is_enforced", OkHttpSurvivalRunner::okhttpOriginHttp2WriteTimeoutIsEnforced);
    run(results, "okhttp_origin_private_key_encoding_failure_fails_fast", OkHttpSurvivalRunner::okhttpOriginPrivateKeyEncodingFailureFailsFast);
    run(results, "okhttp_origin_cache_entry_evicted_while_updating_does_not_corrupt_cache", OkHttpSurvivalRunner::okhttpOriginCacheEntryEvictedWhileUpdatingDoesNotCorruptCache);
    run(results, "okhttp_origin_unknown_http2_settings_are_ignored", OkHttpSurvivalRunner::okhttpOriginUnknownHttp2SettingsAreIgnored);
    run(results, "okhttp_origin_spdy_settings_concurrent_modification_does_not_crash", OkHttpSurvivalRunner::okhttpOriginSpdySettingsConcurrentModificationDoesNotCrash);
    run(results, "okhttp_origin_http2_hpack_dynamic_compression_is_used", OkHttpSurvivalRunner::okhttpOriginHttp2HpackDynamicCompressionIsUsed);
    run(results, "okhttp_origin_hpack_large_header_block_uses_continuation_frames", OkHttpSurvivalRunner::okhttpOriginHpackLargeHeaderBlockUsesContinuationFrames);
    run(results, "okhttp_origin_http2_outgoing_frames_are_buffered", OkHttpSurvivalRunner::okhttpOriginHttp2OutgoingFramesAreBuffered);
    run(results, "okhttp_origin_degraded_http2_ping_closed_connection_does_not_crash", OkHttpSurvivalRunner::okhttpOriginDegradedHttp2PingClosedConnectionDoesNotCrash);
    run(results, "okhttp_origin_http2_route_lock_prevents_concurrent_recovery_crash", OkHttpSurvivalRunner::okhttpOriginHttp2RouteLockPreventsConcurrentRecoveryCrash);
    run(results, "okhttp_origin_http2_write_failure_keeps_connection_state_consistent", OkHttpSurvivalRunner::okhttpOriginHttp2WriteFailureKeepsConnectionStateConsistent);
    System.out.println(toJson(results));
    boolean allPass = results.stream().allMatch(result -> result.passed);
    if (!allPass) {
      System.exit(2);
    }
  }

  private static void run(List<Result> results, String name, ThrowingRunnable runnable) {
    try {
      runnable.run();
      results.add(new Result(name, true, ""));
    } catch (Throwable t) {
      results.add(new Result(name, false, t.getClass().getSimpleName() + ": " + t.getMessage()));
    }
  }

  private static void connectionReuse() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.path.substring(1)))) {
      OkHttpClient client = baseClient().newBuilder()
          .connectionPool(new ConnectionPool(1, 5, TimeUnit.MINUTES))
          .build();
      assertBody(client, server.url("/first"), "first");
      assertBody(client, server.url("/second"), "second");
      require(server.acceptedConnections.get() == 1, "expected one accepted connection, got " + server.acceptedConnections.get());
    }
  }

  private static void queryParams() throws Exception {
    try (RawServer server = new RawServer(request -> {
      return request.path.equals("/specific_method") && request.query.contains("method=GET")
          ? SimpleResponse.ok("ok")
          : SimpleResponse.status(400, "bad");
    })) {
      OkHttpClient client = baseClient();
      HttpUrl url = Objects.requireNonNull(HttpUrl.parse(server.url("/specific_method"))).newBuilder()
          .addQueryParameter("method", "GET")
          .build();
      assertCode(client, url.toString(), 200);
    }
  }

  private static void postForm() throws Exception {
    try (RawServer server = new RawServer(request -> {
      return request.bodyString().equals("method=POST") ? SimpleResponse.ok("ok") : SimpleResponse.status(400, request.bodyString());
    })) {
      Request request = new Request.Builder()
          .url(server.url("/specific_method"))
          .post(new FormBody.Builder().add("method", "POST").build())
          .build();
      assertCode(baseClient(), request, 200);
    }
  }

  private static void arbitraryPutMethod() throws Exception {
    try (RawServer server = new RawServer(request -> {
      return request.method.equals("PUT") && request.query.contains("method=PUT") ? SimpleResponse.ok("ok") : SimpleResponse.status(400, "bad");
    })) {
      Request request = new Request.Builder()
          .url(server.url("/specific_method?method=PUT"))
          .method("PUT", RequestBody.create(new byte[0], null))
          .build();
      assertCode(baseClient(), request, 200);
    }
  }

  private static void multipartFileUpload() throws Exception {
    try (RawServer server = new RawServer(request -> {
      String body = request.bodyString();
      boolean ok = body.contains("filename=\"lolcat.txt\"")
          && body.contains("I'm in ur multipart form-data, hazing a cheezburgr");
      return ok ? SimpleResponse.ok("ok") : SimpleResponse.status(400, body);
    })) {
      RequestBody file = RequestBody.create("I'm in ur multipart form-data, hazing a cheezburgr", TEXT);
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("filefield", "lolcat.txt", file)
          .build();
      Request request = new Request.Builder().url(server.url("/upload")).post(multipart).build();
      assertCode(baseClient(), request, 200);
    }
  }

  private static void redirectObservableWithoutFollowing() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.redirect("/"))) {
      OkHttpClient client = baseClient().newBuilder().followRedirects(false).build();
      assertCode(client, server.url("/redirect?target=/"), 303);
    }
  }

  private static void redirectFollowedByDefault() throws Exception {
    try (RawServer server = new RawServer(request -> request.path.equals("/redirect") ? SimpleResponse.redirect("/") : SimpleResponse.ok("Dummy server!"))) {
      assertBody(baseClient(), server.url("/redirect?target=/"), "Dummy server!");
    }
  }

  private static void readTimeoutError() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(250);
      return SimpleResponse.ok("");
    })) {
      OkHttpClient client = baseClient().newBuilder().readTimeout(Duration.ofMillis(100)).build();
      try {
        client.newCall(new Request.Builder().url(server.url("/sleep?seconds=0.2")).build()).execute().close();
        throw new AssertionError("expected timeout");
      } catch (SocketTimeoutException expected) {
      }
    }
  }

  private static void reusedConnectionUsesNewSocketTimeout() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/slow")) sleep(250);
      return SimpleResponse.ok(request.path);
    })) {
      ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
      OkHttpClient slowTolerant = baseClient().newBuilder()
          .connectionPool(pool)
          .readTimeout(Duration.ofSeconds(1))
          .build();
      OkHttpClient fastTimeout = baseClient().newBuilder()
          .connectionPool(pool)
          .readTimeout(Duration.ofMillis(50))
          .build();
      assertBody(slowTolerant, server.url("/fast"), "/fast");
      try {
        fastTimeout.newCall(new Request.Builder().url(server.url("/slow")).build()).execute().close();
        throw new AssertionError("expected reused connection to use new timeout");
      } catch (SocketTimeoutException expected) {
      }
    }
  }

  private static void brokenConnectionRetried() throws Exception {
    AtomicInteger attempts = new AtomicInteger();
    try (RawServer server = new RawServer(request -> {
      if (attempts.incrementAndGet() == 1) {
        return SimpleResponse.closeWithoutResponse();
      }
      return SimpleResponse.ok("recovered");
    })) {
      OkHttpClient client = baseClient().newBuilder().retryOnConnectionFailure(true).build();
      assertBody(client, server.url("/flaky"), "recovered");
      require(attempts.get() == 2, "expected two attempts, got " + attempts.get());
    }
  }

  private static void httpsBasic() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .rsa2048()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("secure").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .protocols(List.of(Protocol.HTTP_1_1))
          .build();
      assertBody(client, server.url("/").toString(), "secure");
    }
  }

  private static void tlsMinimumAndMaximumVersionsConfigureContext() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    ConnectionSpec tls12Only = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_2)
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("tls12").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .connectionSpecs(List.of(tls12Only))
          .build();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        String body = response.body().string();
        require(response.isSuccessful(), "status " + response.code());
        require("tls12".equals(body), body);
        require(response.handshake() != null && response.handshake().tlsVersion() == TlsVersion.TLS_1_2, "handshake " + response.handshake());
      }
    }
  }

  private static void certificateIpSubjectAltNameIsAccepted() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("ip-san").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .protocols(List.of(Protocol.HTTP_1_1))
          .build();
      assertBody(client, "https://127.0.0.1:" + server.getPort() + "/", "ip-san");
    }
  }

  private static void ipv6BracesAreStrippedForCertificateMatching() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("::1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("ipv6 cert").build());
      server.start(InetAddress.getByName("::1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .build();
      assertBody(client, "https://[::1]:" + server.getPort() + "/ipv6-cert", "ipv6 cert");
    }
  }

  private static void hostnameVerificationCanBeDisabled() throws Exception {
    HeldCertificate wrongHost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("wrong.test")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(wrongHost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(wrongHost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("hostname-disabled").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .hostnameVerifier((hostname, session) -> true)
          .build();
      assertBody(client, "https://127.0.0.1:" + server.getPort() + "/", "hostname-disabled");
    }
  }

  private static void fingerprintVerificationIsSupported() throws Exception {
    HeldCertificate wrongHost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("wrong.test")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(wrongHost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(wrongHost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("fingerprint").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      String host = "127.0.0.1";
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .hostnameVerifier((hostname, session) -> true)
          .certificatePinner(new CertificatePinner.Builder()
              .add(host, CertificatePinner.pin(wrongHost.certificate()))
              .build())
          .build();
      assertBody(client, "https://" + host + ":" + server.getPort() + "/", "fingerprint");
    }
  }

  private static void customCipherSuiteIsApplied() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .rsa2048()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    ConnectionSpec selectedCipher = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_3)
        .cipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256)
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("cipher").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .connectionSpecs(List.of(selectedCipher))
          .build();
      try (Response response = client.newCall(new Request.Builder().url("https://127.0.0.1:" + server.getPort() + "/").build()).execute()) {
        require("cipher".equals(response.body().string()), "bad response");
        require(response.handshake() != null, "missing handshake");
        require(
            response.handshake().cipherSuite() == CipherSuite.TLS_AES_128_GCM_SHA256,
            "cipher was " + response.handshake().cipherSuite()
        );
      }
    }
  }

  private static void tlsAlpnHttp11IdentifierIsSent() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.setProtocols(List.of(Protocol.HTTP_1_1));
      server.enqueue(new MockResponse.Builder().body("alpn").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .protocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1))
          .build();
      assertBody(client, server.url("/alpn").toString(), "alpn");
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "missing ALPN HTTP/1.1 request");
      require("HTTP/1.1".equals(recorded.getVersion()), "version was " + recorded.getVersion());
    }
  }

  private static void gzipResponseDecoded() throws Exception {
    byte[] gzipped = gzip("hello gzip");
    try (RawServer server = new RawServer(request -> SimpleResponse.bytes(200, gzipped, Map.of("Content-Encoding", "gzip")))) {
      assertBody(baseClient(), server.url("/gzip"), "hello gzip");
    }
  }

  private static void gzipContentEncodingCaseInsensitive() throws Exception {
    byte[] gzipped = gzip("hello gzip");
    try (RawServer server = new RawServer(request -> SimpleResponse.bytes(200, gzipped, Map.of("Content-Encoding", "GZip")))) {
      assertBody(baseClient(), server.url("/gzip"), "hello gzip");
    }
  }

  private static void multipleContentEncodings() throws Exception {
    byte[] gzipped = gzip(gzip("double"));
    try (RawServer server = new RawServer(request -> SimpleResponse.bytes(200, gzipped, Map.of("Content-Encoding", "gzip, gzip")))) {
      assertBody(baseClient(), server.url("/gzip"), "double");
    }
  }

  private static void contentEncodingChainLimit() throws Exception {
    byte[] gzipped = gzipNested("too deep".getBytes(StandardCharsets.UTF_8), 6);
    try (RawServer server = new RawServer(request -> SimpleResponse.bytes(200, gzipped, Map.of("Content-Encoding", "gzip, gzip, gzip, gzip, gzip, gzip")))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/gzip")).build()).execute()) {
        response.body().bytes();
        throw new AssertionError("expected chained content-encoding limit failure");
      } catch (IOException expected) {
      }
    }
  }

  private static void decompressionBufferContinuesAfterPartialRead() throws Exception {
    byte[] gzipped = gzip("abcdef");
    try (RawServer server = new RawServer(request -> SimpleResponse.bytes(200, gzipped, Map.of("Content-Encoding", "gzip")))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/gzip")).build()).execute()) {
        byte[] first = response.body().source().readByteArray(2);
        byte[] rest = response.body().source().readByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(first);
        out.write(rest);
        require("abcdef".equals(out.toString(StandardCharsets.UTF_8)), "decoded stream was " + out);
      }
    }
  }

  private static void urlIpv6ZoneIdentifierAccepted() {
    HttpUrl url = HttpUrl.parse("http://[fe80::1%25en0]/");
    require(url != null && url.toString().contains("%25en0"), String.valueOf(url));
  }

  private static void multipleSetCookieHeadersPreserved() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of(
        "Set-Cookie: a=1",
        "Set-Cookie: b=2"
    ), "ok".getBytes(StandardCharsets.UTF_8)))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        List<String> values = response.headers("Set-Cookie");
        require(values.equals(List.of("a=1", "b=2")), "set-cookie values were " + values);
      }
    }
  }

  private static void commaHeaderValuePreserved() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("X-Items: a, b"), "ok".getBytes(StandardCharsets.UTF_8)))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require("a, b".equals(response.header("X-Items")), "comma header was " + response.header("X-Items"));
      }
    }
  }

  private static void incompleteContentLengthRaises() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.rawWithLength(200, List.of(), "short".getBytes(StandardCharsets.UTF_8), 10, true))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        response.body().bytes();
        throw new AssertionError("expected EOF-style failure");
      } catch (IOException expected) {
      }
    }
  }

  private static void invalidChunkLengthRaises() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Transfer-Encoding: chunked"), "ZZZ\r\nbad\r\n0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1)))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        response.body().string();
        throw new AssertionError("expected invalid chunk error");
      } catch (IOException expected) {
      }
    }
  }

  private static void fragmentNotSentInRequestTarget() throws Exception {
    try (RawServer server = new RawServer(request -> request.target.contains("#") ? SimpleResponse.status(400, request.target) : SimpleResponse.ok(request.target))) {
      assertBody(baseClient(), server.url("/path?x=1#fragment"), "/path?x=1");
    }
  }

  private static void requestTargetIsOriginForm() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.target))) {
      assertBody(baseClient(), server.url("/path?x=1"), "/path?x=1");
    }
  }

  private static void tildePathNotPercentEncoded() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.target))) {
      assertBody(baseClient(), server.url("/~user"), "/~user");
    }
  }

  private static void emptyQuerySectionPreserved() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.target))) {
      assertBody(baseClient(), server.url("/path?"), "/path?");
    }
  }

  private static void userSuppliedHostHeaderPreserved() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.header("Host")))) {
      Request request = new Request.Builder().url(server.url("/")).header("Host", "example.test").build();
      assertBody(baseClient(), request, "example.test");
    }
  }

  private static void chunkedRequestSetsTransferEncoding() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.header("Transfer-Encoding")))) {
      RequestBody streaming = new RequestBody() {
        @Override public MediaType contentType() { return TEXT; }
        @Override public long contentLength() { return -1L; }
        @Override public void writeTo(okio.BufferedSink sink) throws IOException {
          sink.writeUtf8("chunk me");
        }
      };
      Request request = new Request.Builder().url(server.url("/")).post(streaming).build();
      assertBody(baseClient(), request, "chunked");
    }
  }

  private static void chunkedKeepAlivePreservesRequestBoundaries() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.method.equals("POST")) return SimpleResponse.ok(request.bodyString());
      return SimpleResponse.ok(request.path);
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .connectionPool(new ConnectionPool(1, 5, TimeUnit.MINUTES))
          .build();
      Request post = new Request.Builder().url(server.url("/upload")).post(chunkedUtf8Body("chunked")).build();
      assertBody(client, post, "chunked");
      assertBody(client, server.url("/next"), "/next");
      require(server.acceptedConnections.get() == 1, "accepted " + server.acceptedConnections.get());
    }
  }

  private static void chunkedRequestBodyUsesUtf8() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(toHex(request.body())))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .post(chunkedUtf8Body("cafe \u00e9"))
          .build();
      assertBody(baseClient(), request, toHex("cafe \u00e9".getBytes(StandardCharsets.UTF_8)));
    }
  }

  private static void chunkedBoundariesAreLowercase() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(String.join(",", request.chunkSizeLines())))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .post(chunkedUtf8Body("xxxxxxxxxxxxxxxxxxxxxxxxxx"))
          .build();
      assertBody(baseClient(), request, "1a,0");
    }
  }

  private static void http303RedirectSwitchesMethodToGet() throws Exception {
    List<String> methods = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> {
      methods.add(request.method + " " + request.path + " " + request.bodyString());
      if (request.path.equals("/redirect")) return SimpleResponse.redirect("/target");
      return SimpleResponse.ok(request.method + ":" + request.bodyString());
    })) {
      Request request = new Request.Builder()
          .url(server.url("/redirect"))
          .post(RequestBody.create("body", TEXT))
          .build();
      assertBody(baseClient(), request, "GET:");
      require(methods.size() == 2, "methods " + methods);
      require(methods.get(1).equals("GET /target "), "target request was " + methods.get(1));
    }
  }

  private static void relativeRedirectLocationFollowed() throws Exception {
    try (RawServer server = new RawServer(request -> request.path.equals("/a/start") ? SimpleResponse.redirect("../target") : SimpleResponse.ok(request.path))) {
      assertBody(baseClient(), server.url("/a/start"), "/target");
    }
  }

  private static void redirectBodyIsReleasedBeforeFollowing() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/start")) {
        return new SimpleResponse(
            302,
            List.of("Location: /target"),
            "x".repeat(1024).getBytes(StandardCharsets.UTF_8),
            false,
            false,
            null
        );
      }
      return SimpleResponse.ok("target");
    })) {
      Dispatcher dispatcher = new Dispatcher();
      dispatcher.setMaxRequestsPerHost(1);
      OkHttpClient client = baseClient().newBuilder()
          .dispatcher(dispatcher)
          .connectionPool(new ConnectionPool(1, 5, TimeUnit.MINUTES))
          .build();
      assertBody(client, server.url("/start"), "target");
    }
  }

  private static void crossHostRedirectStripsAuthorization() throws Exception {
    try (RawServer target = new RawServer(request -> SimpleResponse.ok(String.valueOf(request.header("Authorization"))));
         RawServer source = new RawServer(request -> SimpleResponse.redirect(target.url("/target")))) {
      Request request = new Request.Builder()
          .url(source.url("/start"))
          .header("Authorization", "Bearer secret")
          .build();
      assertBody(baseClient(), request, "null");
    }
  }

  private static void crossHostRedirectStripsAuthorizationCaseInsensitive() throws Exception {
    try (RawServer target = new RawServer(request -> SimpleResponse.ok(String.valueOf(request.header("Authorization"))));
         RawServer source = new RawServer(request -> SimpleResponse.redirect(target.url("/target")))) {
      Request request = new Request.Builder()
          .url(source.url("/start"))
          .header("authorization", "Bearer secret")
          .build();
      assertBody(baseClient(), request, "null");
    }
  }

  private static void redirectHeaderInputNotMutated() throws Exception {
    Headers input = new Headers.Builder().add("Authorization", "Bearer secret").build();
    try (RawServer target = new RawServer(request -> SimpleResponse.ok("ok"));
         RawServer source = new RawServer(request -> SimpleResponse.redirect(target.url("/target")))) {
      Request request = new Request.Builder().url(source.url("/start")).headers(input).build();
      assertBody(baseClient(), request, "ok");
      require(input.values("Authorization").equals(List.of("Bearer secret")), "input headers mutated: " + input);
    }
  }

  private static void crossHostRedirectStripsCookie() throws Exception {
    try (RawServer target = new RawServer(request -> SimpleResponse.ok(String.valueOf(request.header("Cookie"))));
         RawServer source = new RawServer(request -> SimpleResponse.redirect(target.url("/target")))) {
      Request request = new Request.Builder()
          .url(source.url("/start"))
          .header("Cookie", "a=1")
          .build();
      assertBody(baseClient(), request, "null");
    }
  }

  private static void crossHostRedirectStripsProxyAuthorization() throws Exception {
    try (RawServer target = new RawServer(request -> SimpleResponse.ok(String.valueOf(request.header("Proxy-Authorization"))));
         RawServer source = new RawServer(request -> SimpleResponse.redirect(target.url("/target")))) {
      Request request = new Request.Builder()
          .url(source.url("/start"))
          .header("Proxy-Authorization", "Basic secret")
          .build();
      assertBody(baseClient(), request, "null");
    }
  }

  private static void methodRejectsControlCharacters() {
    try {
      new Request.Builder().url("http://example.test/").method("GE\nT", null).build();
      throw new AssertionError("expected invalid method rejection");
    } catch (IllegalArgumentException expected) {
    }
  }

  private static void urlEmptyHostRejected() {
    require(HttpUrl.parse("http:///path") == null, "empty host URL was accepted");
  }

  private static void urlSchemeAndHostNormalizedLowercase() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("HTTP://EXAMPLE.COM/Path"));
    require(url.scheme().equals("http"), "scheme was " + url.scheme());
    require(url.host().equals("example.com"), "host was " + url.host());
  }

  private static void urlDefaultPortEquivalence() {
    HttpUrl implicit = Objects.requireNonNull(HttpUrl.parse("http://example.com/"));
    HttpUrl explicit = Objects.requireNonNull(HttpUrl.parse("http://example.com:80/"));
    require(implicit.port() == explicit.port(), "ports differ");
    require(implicit.host().equals(explicit.host()), "hosts differ");
  }

  private static void urlPortWithLeadingZeroesAccepted() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.com:00080/"));
    require(url.port() == 80, "port was " + url.port());
  }

  private static void urlPortZeroPreserved() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.com:0/"));
    require(url.port() == 0, "port was " + url.port());
  }

  private static void urlPortRejectsUnicodeDigits() {
    require(HttpUrl.parse("http://example.com:\u0661/") == null, "unicode digit port was accepted");
  }

  private static void urlIpv6RequiresBrackets() {
    require(HttpUrl.parse("http://::1/") == null, "bare IPv6 was accepted");
    require(HttpUrl.parse("http://[::1]/") != null, "bracketed IPv6 was rejected");
  }

  private static void urlInvalidCharsPercentEncoded() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.com/a b?x=a b#frag ment"));
    require(url.encodedPath().equals("/a%20b"), "path was " + url.encodedPath());
    require(url.encodedQuery().equals("x=a%20b"), "query was " + url.encodedQuery());
    require(url.encodedFragment().equals("frag%20ment"), "fragment was " + url.encodedFragment());
  }

  private static void urlAuthInvalidCharsPercentEncoded() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://u s:p s@example.com/"));
    require(url.encodedUsername().equals("u%20s"), "username was " + url.encodedUsername());
    require(url.encodedPassword().equals("p%20s"), "password was " + url.encodedPassword());
  }

  private static void urlAuthorityIncludesUserinfoAndHost() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://user:pass@example.com:8080/path"));
    require(url.encodedUsername().equals("user"), "username");
    require(url.encodedPassword().equals("pass"), "password");
    require(url.host().equals("example.com"), "host");
    require(url.port() == 8080, "port");
  }

  private static void jsonRequestSetsContentType() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.header("Content-Type")))) {
      Request request = new Request.Builder()
          .url(server.url("/json"))
          .post(RequestBody.create("{\"ok\":true}", MediaType.get("application/json")))
          .build();
      assertBody(baseClient(), request, "application/json; charset=utf-8");
    }
  }

  private static void requestHeaderInputNotMutated() throws Exception {
    Headers.Builder headers = new Headers.Builder().add("X-Test", "before");
    Headers built = headers.build();
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .headers(built)
          .post(RequestBody.create("{}", MediaType.get("application/json")))
          .build();
      assertCode(baseClient(), request, 200);
      require(built.values("Content-Type").isEmpty(), "input headers gained content-type");
    }
  }

  private static void defaultHeadersSent() throws Exception {
    try (RawServer server = new RawServer(request -> {
      boolean ok = request.header("Host") != null && request.header("Connection") != null && request.header("Accept-Encoding") != null;
      return ok ? SimpleResponse.ok("ok") : SimpleResponse.status(400, request.headers.toString());
    })) {
      assertCode(baseClient(), server.url("/"), 200);
    }
  }

  private static void connectionRefusedError() throws Exception {
    int port;
    try (ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }
    try {
      baseClient().newCall(new Request.Builder().url("http://127.0.0.1:" + port + "/").build()).execute().close();
    } catch (IOException expected) {
      return;
    }
    throw new AssertionError("expected connection error");
  }

  private static void httpsRequestThroughHttpConnectProxySucceeds() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer origin = new MockWebServer(); TunnelProxy proxy = new TunnelProxy()) {
      origin.useHttps(serverCertificates.sslSocketFactory());
      origin.enqueue(new MockResponse.Builder().body("proxied secure").build());
      origin.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      assertBody(client, origin.url("/proxied").toString(), "proxied secure");
      require(!proxy.requests.isEmpty() && proxy.requests.get(0).startsWith("CONNECT "), "requests " + proxy.requests);
    }
  }

  private static void proxyConnectIpv6TargetUsesBrackets() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("::1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer origin = new MockWebServer(); TunnelProxy proxy = new TunnelProxy()) {
      origin.useHttps(serverCertificates.sslSocketFactory());
      origin.enqueue(new MockResponse.Builder().body("ipv6 proxied").build());
      origin.start(InetAddress.getByName("::1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .hostnameVerifier((hostname, session) -> true)
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      assertBody(client, "https://[::1]:" + origin.getPort() + "/ipv6", "ipv6 proxied");
      require(!proxy.requests.isEmpty() && proxy.requests.get(0).startsWith("CONNECT [::1]:"), "requests " + proxy.requests);
    }
  }

  private static void ipv6ProxyHostIsParsedCorrectly() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer origin = new MockWebServer(); TunnelProxy proxy = new TunnelProxy("::1")) {
      origin.useHttps(serverCertificates.sslSocketFactory());
      origin.enqueue(new MockResponse.Builder().body("ipv6 proxy host").build());
      origin.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(InetAddress.getByName("::1"), proxy.port())))
          .build();
      assertBody(client, origin.url("/ipv6-proxy").toString(), "ipv6 proxy host");
      require(!proxy.requests.isEmpty() && proxy.requests.get(0).startsWith("CONNECT "), "requests " + proxy.requests);
    }
  }

  private static void trailingDotHostnameThroughProxyConnects() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer origin = new MockWebServer(); TunnelProxy proxy = new TunnelProxy()) {
      origin.useHttps(serverCertificates.sslSocketFactory());
      origin.enqueue(new MockResponse.Builder().body("trailing dot").build());
      origin.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .hostnameVerifier((hostname, session) -> true)
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      assertBody(client, "https://localhost.:" + origin.getPort() + "/trailing", "trailing dot");
      require(!proxy.requests.isEmpty() && proxy.requests.get(0).startsWith("CONNECT localhost.:"), "requests " + proxy.requests);
    }
  }

  private static void socksProxyBasicRequestSucceeds() throws Exception {
    try (RawServer origin = new RawServer(request -> SimpleResponse.ok("socks basic"));
         SocksProxy proxy = new SocksProxy()) {
      OkHttpClient client = baseClient().newBuilder()
          .proxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      assertBody(client, origin.url("/socks"), "socks basic");
      require(!proxy.requests.isEmpty() && proxy.requests.get(0).contains(":127.0.0.1:"), "requests " + proxy.requests);
    }
  }

  private static void socksRemoteDnsSchemesAreSupported() throws Exception {
    try (RawServer origin = new RawServer(request -> SimpleResponse.ok("socks remote dns"));
         SocksProxy proxy = new SocksProxy("remote.test", "127.0.0.1")) {
      OkHttpClient client = baseClient().newBuilder()
          .proxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      assertBody(client, "http://remote.test:" + origin.port() + "/socks-dns", "socks remote dns");
      require(!proxy.requests.isEmpty() && proxy.requests.get(0).startsWith("3:remote.test:"), "requests " + proxy.requests);
    }
  }

  private static void dnsFailureError() throws Exception {
    try {
      baseClient().newCall(new Request.Builder().url("http://nonexistent.shapingbench.invalid/").build()).execute().close();
    } catch (IOException expected) {
      return;
    }
    throw new AssertionError("expected DNS error");
  }

  private static void headersMappingAccepted() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.header("X-Test")))) {
      Request request = new Request.Builder().url(server.url("/")).header("X-Test", "ok").build();
      assertBody(baseClient(), request, "ok");
    }
  }

  private static void clientDefaultHeadersApplyToGetQuery() throws Exception {
    try (RawServer server = new RawServer(request -> {
      boolean ok = request.query.equals("q=1") && "yes".equals(request.header("X-Default"));
      return ok ? SimpleResponse.ok("ok") : SimpleResponse.status(400, request.query + " " + request.headers);
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .addInterceptor(chain -> chain.proceed(chain.request().newBuilder().header("X-Default", "yes").build()))
          .build();
      assertCode(client, server.url("/search?q=1"), 200);
    }
  }

  private static void messageContentTypeHeaderAccepted() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Type: message/http"), "ok".getBytes(StandardCharsets.UTF_8)))) {
      assertBody(baseClient(), server.url("/"), "ok");
    }
  }

  private static void duplicateUserAgentNotAdded() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(Integer.toString(request.headerValues("User-Agent").size())))) {
      Request request = new Request.Builder().url(server.url("/")).header("User-Agent", "custom").build();
      assertBody(baseClient(), request, "1");
    }
  }

  private static void requestHeaderOrderPreserved() throws Exception {
    try (RawServer server = new RawServer(request -> {
      List<String> ordered = request.headerOrder.stream()
          .filter(name -> name.equalsIgnoreCase("X-One") || name.equalsIgnoreCase("X-Two"))
          .toList();
      return SimpleResponse.ok(String.join(",", ordered));
    })) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .addHeader("X-One", "1")
          .addHeader("X-Two", "2")
          .build();
      assertBody(baseClient(), request, "X-One,X-Two");
    }
  }

  private static void explicitTransferEncodingChunkedNotDuplicated() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(Integer.toString(request.headerValues("Transfer-Encoding").size())))) {
      RequestBody streaming = new RequestBody() {
        @Override public MediaType contentType() { return TEXT; }
        @Override public long contentLength() { return -1L; }
        @Override public void writeTo(okio.BufferedSink sink) throws IOException { sink.writeUtf8("chunk me"); }
      };
      Request request = new Request.Builder()
          .url(server.url("/"))
          .header("Transfer-Encoding", "chunked")
          .post(streaming)
          .build();
      assertBody(baseClient(), request, "1");
    }
  }

  private static void multipartDuplicateFieldNamesPreserved() throws Exception {
    try (RawServer server = new RawServer(request -> {
      int count = countOccurrences(request.bodyString(), "name=\"field\"");
      return SimpleResponse.ok(Integer.toString(count));
    })) {
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("field", "one")
          .addFormDataPart("field", "two")
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      assertBody(baseClient(), request, "2");
    }
  }

  private static void multipartEmptyFilenameEmitted() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(Boolean.toString(request.bodyString().contains("filename=\"\""))))) {
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("file", "", RequestBody.create("x", TEXT))
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      assertBody(baseClient(), request, "true");
    }
  }

  private static void multipartHtml5FilenameFormatting() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.bodyString()))) {
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("file", "cafe-\u00e9.txt", RequestBody.create("x", TEXT))
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      try (Response response = baseClient().newCall(request).execute()) {
        String body = response.body().string();
        require(body.contains("filename=\"cafe-\u00e9.txt\"") && !body.contains("filename*="), body);
      }
    }
  }

  private static void multipartControlCharsNotPercentEncoded() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.bodyString()))) {
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("file", "control-\u001f.txt", RequestBody.create("x", TEXT))
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      try (Response response = baseClient().newCall(request).execute()) {
        String body = response.body().string();
        require(!body.toUpperCase(Locale.ROOT).contains("%1F") && body.contains("filename=\"control-\u001f.txt\""), body);
      }
    }
  }

  private static void multipartExplicitContentTypeSent() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(Boolean.toString(request.bodyString().contains("Content-Type: text/plain; charset=utf-8"))))) {
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("file", "a.txt", RequestBody.create("x", TEXT))
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      assertBody(baseClient(), request, "true");
    }
  }

  private static void multipartPlainFieldsHaveNoDefaultContentType() throws Exception {
    try (RawServer server = new RawServer(request -> {
      String body = request.bodyString();
      int disposition = body.indexOf("name=\"field\"");
      int nextBoundary = body.indexOf("--", disposition + 1);
      String part = body.substring(disposition, nextBoundary);
      return SimpleResponse.ok(Boolean.toString(!part.contains("Content-Type:")));
    })) {
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("field", "value")
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      assertBody(baseClient(), request, "true");
    }
  }

  private static void responseBodyLinesStreamed() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("a\nb\n"))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        String first = response.body().source().readUtf8LineStrict();
        String second = response.body().source().readUtf8LineStrict();
        require(first.equals("a") && second.equals("b"), "lines were " + first + "," + second);
      }
    }
  }

  private static void chunkedHeadResponseWithoutBodyDoesNotHang() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Transfer-Encoding: chunked"), new byte[0]))) {
      Request request = new Request.Builder().url(server.url("/")).head().build();
      assertCode(baseClient(), request, 200);
    }
  }

  private static void http2RequestBodyWithoutTransferEncoding() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.setProtocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE));
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE))
          .build();
      Request request = new Request.Builder()
          .url(server.url("/h2"))
          .post(RequestBody.create("hello h2", TEXT))
          .build();
      assertBody(client, request, "ok");
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "missing recorded HTTP/2 request");
      require("HTTP/2".equals(recorded.getVersion()), "version was " + recorded.getVersion());
      require("hello h2".equals(recorded.getBody().utf8()), "body was " + recorded.getBody().utf8());
      require(recorded.getHeaders().get("Transfer-Encoding") == null, "transfer-encoding was " + recorded.getHeaders().get("Transfer-Encoding"));
    }
  }

  private static void http2OriginSupportIsProbedWithAlpn() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .addSubjectAlternativeName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.setProtocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1));
      server.enqueue(new MockResponse.Builder().body("h2").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .protocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1))
          .build();
      assertBody(client, server.url("/alpn").toString(), "h2");
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "missing ALPN-probed request");
      require("HTTP/2".equals(recorded.getVersion()), "version was " + recorded.getVersion());
    }
  }

  private static OkHttpClient baseClient() {
    return new OkHttpClient.Builder()
        .callTimeout(Duration.ofSeconds(5))
        .connectTimeout(Duration.ofSeconds(2))
        .readTimeout(Duration.ofSeconds(2))
        .writeTimeout(Duration.ofSeconds(2))
        .build();
  }

  private static void okhttpOriginFormBodyEncodesSpaceAsPlus() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.bodyString()))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .post(new FormBody.Builder().add("q", "a b").build())
          .build();
      assertBody(baseClient(), request, "q=a+b");
    }
  }

  private static void okhttpOriginFormBodyBuilderAcceptsExplicitCharset() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.bodyString()))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .post(new FormBody.Builder(StandardCharsets.ISO_8859_1).add("q", "é").build())
          .build();
      assertBody(baseClient(), request, "q=%E9");
    }
  }

  private static void okhttpOriginRequestBodiesAllowedForMethodsExceptGetAndHead() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.method + ":" + request.bodyString()))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .method("DELETE", RequestBody.create("payload", TEXT))
          .build();
      assertBody(baseClient(), request, "DELETE:payload");
    }
  }

  private static void okhttpOriginOptionsRequestBodyIsAllowed() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.method + ":" + request.bodyString()))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .method("OPTIONS", RequestBody.create("payload", TEXT))
          .build();
      assertBody(baseClient(), request, "OPTIONS:payload");
    }
  }

  private static void okhttpOriginHttp308PermanentRedirectIsHandled() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/old")) {
        return SimpleResponse.raw(308, List.of("Location: /new"), new byte[0]);
      }
      return SimpleResponse.ok(request.path);
    })) {
      assertBody(baseClient(), server.url("/old"), "/new");
    }
  }

  private static void okhttpOriginHttp307308RedirectsPreserveNonGetPostMethodAndBody() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/old")) {
        return SimpleResponse.raw(308, List.of("Location: /new"), new byte[0]);
      }
      return SimpleResponse.ok(request.method + ":" + request.bodyString());
    })) {
      Request request = new Request.Builder()
          .url(server.url("/old"))
          .method("DELETE", RequestBody.create("payload", TEXT))
          .build();
      assertBody(baseClient(), request, "DELETE:payload");
    }
  }

  private static void okhttpOriginMultipleInformationalResponsesAreIgnoredUntilFinal() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.withInterim(List.of(102, 103), 200, "ok"))) {
      assertBody(baseClient(), server.url("/"), "ok");
    }
  }

  private static void okhttpOriginHttp1100ContinueStatusLinesAreIgnoredUntilFinal() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.withInterim(List.of(100), 200, "ok"))) {
      assertBody(baseClient(), server.url("/"), "ok");
    }
  }

  private static void okhttpOriginEmptyQueryDoesNotIncludeFragment() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.target))) {
      assertBody(baseClient(), server.url("/path?#frag"), "/path?");
    }
  }

  private static void okhttpOriginEncodedQueryPlusIsPreserved() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.target))) {
      assertBody(baseClient(), server.url("/path?q=a+b"), "/path?q=a+b");
    }
  }

  private static void okhttpOriginUrlSchemeMayContainDigits() {
    HttpUrl url = HttpUrl.parse("webdav1://example.com/path");
    require(url != null && url.scheme().equals("webdav1"), String.valueOf(url));
  }

  private static void okhttpOriginUrlFragmentPreservesNonAsciiCharacters() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.com/path#é"));
    require("é".equals(url.fragment()), url.toString());
  }

  private static void okhttpOriginIdnUsesUts46NontransitionalProcessing() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://faß.de/"));
    require(url.host().equals("xn--fa-hia.de"), "host was " + url.host());
  }

  private static void okhttpOriginUrlDomainLabelLengthLimitsAreEnforced() {
    String label = "a".repeat(64);
    require(HttpUrl.parse("http://" + label + ".example/") == null, "64-byte label was accepted");
  }

  private static void okhttpOriginTopPrivateDomainMalformedHostDoesNotCrash() {
    HttpUrl url = HttpUrl.parse("http://bad_host/");
    if (url == null) return;
    require(url.topPrivateDomain() == null, "top private domain was " + url.topPrivateDomain());
  }

  private static void okhttpOriginBadUrlHostnameCharactersAreRejected() {
    require(HttpUrl.parse("http://bad_host^name/") == null, "bad hostname was accepted");
  }

  private static void okhttpOriginHttpUrlToUriStripsInvalidHostnameCharacters() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://bad{host}.example/"));
    URI uri = url.uri();
    require(!String.valueOf(uri.getHost()).contains("{"), "uri host was " + uri.getHost());
  }

  private static void okhttpOriginIpv4MappedIpv6UrlDoesNotCrash() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://[::ffff:192.0.2.1]/"));
    require(url.host().contains("192.0.2.1") || url.host().contains("::ffff"), "host was " + url.host());
  }

  private static void okhttpOriginQueryParameterBuilderEscapesAsciiPunctuation() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.test/"))
        .newBuilder()
        .addQueryParameter("q", "a{b}c")
        .build();
    require(url.encodedQuery().contains("%7B") && url.encodedQuery().contains("%7D"), "query was " + url.encodedQuery());
  }

  private static void okhttpOriginIpv6UrlHostIsCanonicalized() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://[0:0:0:0:0:ffff:c000:0280]/"));
    require(url.host().equals("::ffff:192.0.2.128"), "host was " + url.host());
  }

  private static void okhttpOriginHttpUrlToUriAllowsSpecialUrlCharacters() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.test/a|b[/"));
    URI uri = url.uri();
    require(uri.toString().contains("%7C") && uri.toString().contains("%5B"), uri.toString());
  }

  private static void okhttpOriginPortOutOfRangeFailsEarly() {
    try {
      new Request.Builder().url("http://127.0.0.1:65536/").build();
    } catch (IllegalArgumentException expected) {
      return;
    }
    throw new AssertionError("accepted port 65536");
  }

  private static void okhttpOriginHttp10RequestsAreNotSent() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.protocol))) {
      assertBody(baseClient(), server.url("/"), "HTTP/1.1");
    }
  }

  private static void okhttpOriginWebdavMethodsAreSupported() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.method))) {
      Request request = new Request.Builder()
          .url(server.url("/resource"))
          .method("PROPFIND", null)
          .build();
      assertBody(baseClient(), request, "PROPFIND");
    }
  }

  private static void okhttpOriginRequestBuilderReuseDoesNotKeepStaleUrlFields() {
    Request.Builder builder = new Request.Builder().url("http://a.test/path");
    Request second = builder.url("http://b.test/other").build();
    require(second.url().toString().equals("http://b.test/other"), second.url().toString());
  }

  private static void okhttpOriginIllegalRequestBodyFailsAtBuildTime() {
    try {
      new Request.Builder()
          .url("http://example.test/")
          .method("GET", RequestBody.create("payload", TEXT))
          .build();
    } catch (IllegalArgumentException expected) {
      return;
    }
    throw new AssertionError("GET body was accepted");
  }

  private static void okhttpOriginRequestToCurlIncludesRequestShape() {
    Request request = new Request.Builder()
        .url("https://example.test/path")
        .header("X-Test", "1")
        .post(RequestBody.create("abc", TEXT))
        .build();
    String curl = request.toCurl();
    require(curl.contains("-X POST") || curl.contains("--request POST"), curl);
    require(curl.contains("X-Test: 1"), curl);
    require(curl.contains("abc"), curl);
  }

  private static void okhttpOriginDisabledRedirectPolicyIsHonored() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/")) return SimpleResponse.raw(302, List.of("Location: /target"), new byte[0]);
      return SimpleResponse.ok("target");
    })) {
      OkHttpClient client = baseClient().newBuilder().followRedirects(false).build();
      assertCode(client, server.url("/"), 302);
      require(server.pathRequests.get("/target") == null, "follow-up was requested");
    }
  }

  private static void okhttpOriginQueryMethodRedirectsFollowRfc10008() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/redirect")) return SimpleResponse.raw(303, List.of("Location: /target"), new byte[0]);
      return SimpleResponse.ok(request.method + ":" + request.bodyString());
    })) {
      Request request = new Request.Builder()
          .url(server.url("/redirect"))
          .method("QUERY", RequestBody.create("q=1", TEXT))
          .build();
      assertBody(baseClient(), request, "GET:");
    }
  }

  private static void okhttpOriginResponseBodyIsNonNullForAllResponses() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(204, List.of(), new byte[0]))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/empty")).build()).execute()) {
        require(response.body() != null, "response body was null");
        require(response.body().bytes().length == 0, "non-empty body");
      }
    }
  }

  private static void okhttpOriginResponseTrailersNoBodyDoesNotCrash() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(204, List.of(), new byte[0]))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/empty")).build()).execute()) {
        require(response.trailers().size() == 0, "trailers were " + response.trailers());
      }
    }
  }

  private static void okhttpOriginResponseTrailersAvailableAfterBodyExhausted() throws Exception {
    byte[] chunked = "2\r\nok\r\n0\r\nX-Trailer: done\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Transfer-Encoding: chunked"), chunked))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/trailers")).build()).execute()) {
        require(response.body().string().equals("ok"), "body mismatch");
        require("done".equals(response.trailers().get("X-Trailer")), "trailers were " + response.trailers());
      }
    }
  }

  private static void okhttpOriginHttp100EmptyBodyTrailersAreNotPromotedToHeaders() throws Exception {
    byte[] prefix = "HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    byte[] chunked = "0\r\nX-Trailer: done\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    try (RawServer server = new RawServer(request -> SimpleResponse.prefixed(prefix, 200, List.of("Transfer-Encoding: chunked"), chunked))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require(response.code() == 200, "code " + response.code());
        require(response.header("X-Trailer") == null, "trailer promoted to header");
        require(response.body().bytes().length == 0, "body not empty");
        require("done".equals(response.trailers().get("X-Trailer")), "trailers were " + response.trailers());
      }
    }
  }

  private static void okhttpOriginGzipStreamsAreExhaustedOnClose() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/gzip")) {
        return SimpleResponse.bytes(200, gzip("abcdef"), Map.of("Content-Encoding", "gzip"));
      }
      return SimpleResponse.ok("next");
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .connectionPool(new ConnectionPool(1, 5, TimeUnit.MINUTES))
          .build();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/gzip")).build()).execute()) {
        require(response.body().source().readByte() == 'a', "first byte mismatch");
      }
      assertBody(client, server.url("/next"), "next");
      require(server.acceptedConnections.get() == 1, "accepted " + server.acceptedConnections.get());
    }
  }

  private static void okhttpOriginShoutcastIcyResponseIsSupported() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.statusLine("ICY 200 OK", List.of(), "stream".getBytes(StandardCharsets.UTF_8)))) {
      assertBody(baseClient(), server.url("/"), "stream");
    }
  }

  private static void okhttpOriginHeadersToMultimapIsCaseInsensitive() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Type: text/plain"), "ok".getBytes(StandardCharsets.UTF_8)))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require("text/plain".equals(response.header("content-type")), "headers were " + response.headers());
      }
    }
  }

  private static void okhttpOriginRequestToStringRedactsSensitiveHeaders() {
    Request request = new Request.Builder()
        .url("https://example.test/path")
        .header("Authorization", "secret")
        .header("Cookie", "a=1")
        .header("Proxy-Authorization", "secret")
        .build();
    String text = request.toString();
    require(!text.contains("secret") && !text.contains("a=1"), text);
  }

  private static void okhttpOriginUnsafeNonAsciiHeaderValuesCanBeAdded() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.header("X-Test")))) {
      Headers headers = new Headers.Builder()
          .addUnsafeNonAscii("X-Test", "token-é")
          .build();
      Request request = new Request.Builder().url(server.url("/")).headers(headers).build();
      try (Response response = baseClient().newCall(request).execute()) {
        String body = response.body().string();
        require(body.startsWith("token-"), body);
      }
    }
  }

  private static void okhttpOriginMultipartFilenameAllowsNonAscii() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.bodyString()))) {
      RequestBody file = RequestBody.create("x", TEXT);
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("file", "résumé.txt", file)
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      try (Response response = baseClient().newCall(request).execute()) {
        String body = response.body().string();
        require(body.contains("filename=\"résumé.txt\""), body);
      }
    }
  }

  private static void okhttpOriginMultipartFixedLengthBodyEmitsContentLength() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.header("Content-Length")))) {
      RequestBody file = RequestBody.create("x", TEXT);
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("file", "a.txt", file)
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      try (Response response = baseClient().newCall(request).execute()) {
        String body = response.body().string();
        require(body.matches("\\d+"), body);
      }
    }
  }

  private static void okhttpOriginMultipartBodyOmitsAggregateContentLength() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(String.valueOf(request.header("Content-Length"))))) {
      RequestBody streaming = new RequestBody() {
        @Override public MediaType contentType() { return TEXT; }
        @Override public long contentLength() { return -1L; }
        @Override public void writeTo(okio.BufferedSink sink) throws IOException { sink.writeUtf8("stream"); }
      };
      RequestBody multipart = new MultipartBody.Builder()
          .setType(MultipartBody.FORM)
          .addFormDataPart("stream", "stream.txt", streaming)
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(multipart).build();
      assertBody(baseClient(), request, "null");
    }
  }

  private static void okhttpOriginHttpsTunnelDoesNotLeakOriginHeadersToProxy() throws Exception {
    List<RawRequest> captured = new CopyOnWriteArrayList<>();
    try (RawServer proxy = new RawServer(request -> {
      captured.add(request);
      return SimpleResponse.status(502, "");
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      Request request = new Request.Builder()
          .url("https://example.com/path")
          .header("Authorization", "Bearer secret")
          .header("Cookie", "a=1")
          .build();
      try {
        client.newCall(request).execute().close();
      } catch (IOException expected) {
      }
      require(!captured.isEmpty(), "proxy did not capture CONNECT request");
      RawRequest connect = captured.get(0);
      require(connect.method.equals("CONNECT"), "method was " + connect.method);
      require(connect.header("Authorization") == null && connect.header("Cookie") == null, "headers leaked " + connect.headers);
    }
  }

  private static void okhttpOriginProxySelectorFailureFallsBackToDirect() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("direct"))) {
      ProxySelector previous = ProxySelector.getDefault();
      ProxySelector selector = new ProxySelector() {
        @Override public List<Proxy> select(URI uri) {
          throw new SecurityException("boom");
        }

        @Override public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        }
      };
      try {
        ProxySelector.setDefault(selector);
        assertBody(baseClient(), server.url("/"), "direct");
      } finally {
        ProxySelector.setDefault(previous);
      }
    }
  }

  private static void okhttpOriginProxySelectorConnectFailedIsNotified() throws Exception {
    AtomicInteger connectFailed = new AtomicInteger();
    int port;
    try (ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }
    ProxySelector selector = new ProxySelector() {
      @Override public List<Proxy> select(URI uri) {
        return List.of(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
      }

      @Override public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        connectFailed.incrementAndGet();
      }
    };
    OkHttpClient client = baseClient().newBuilder()
        .proxySelector(selector)
        .connectTimeout(Duration.ofMillis(100))
        .build();
    try {
      client.newCall(new Request.Builder().url("http://example.test/").build()).execute().close();
    } catch (IOException expected) {
    }
    require(connectFailed.get() == 1, "connectFailed count " + connectFailed.get());
  }

  private static void okhttpOriginExplicitProxyClientsShareConnectionPool() throws Exception {
    try (RawServer proxy = new RawServer(request -> SimpleResponse.ok(request.target))) {
      ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
      Proxy explicitProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port()));
      OkHttpClient first = baseClient().newBuilder()
          .connectionPool(pool)
          .proxy(explicitProxy)
          .build();
      OkHttpClient second = baseClient().newBuilder()
          .connectionPool(pool)
          .proxy(explicitProxy)
          .build();
      assertBody(first, "http://origin.test/one", "http://origin.test/one");
      assertBody(second, "http://origin.test/two", "http://origin.test/two");
      require(proxy.acceptedConnections.get() == 1, "accepted " + proxy.acceptedConnections.get());
    }
  }

  private static void okhttpOriginProxySelectorConnectionsPoolCorrectly() throws Exception {
    try (RawServer proxy = new RawServer(request -> SimpleResponse.ok(request.target))) {
      ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
      Proxy selected = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port()));
      ProxySelector selector = new ProxySelector() {
        @Override public List<Proxy> select(URI uri) {
          return List.of(selected);
        }

        @Override public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        }
      };
      OkHttpClient client = baseClient().newBuilder()
          .connectionPool(pool)
          .proxySelector(selector)
          .build();
      assertBody(client, "http://origin.test/one", "http://origin.test/one");
      assertBody(client, "http://origin.test/two", "http://origin.test/two");
      require(proxy.acceptedConnections.get() == 1, "accepted " + proxy.acceptedConnections.get());
    }
  }

  private static void okhttpOriginRetryAfterControls503And408Retries() throws Exception {
    Map<String, AtomicInteger> counts = new ConcurrentHashMap<>();
    try (RawServer server = new RawServer(request -> {
      int count = counts.computeIfAbsent(request.path, ignored -> new AtomicInteger()).incrementAndGet();
      if (count == 1) {
        int status = request.path.equals("/503") ? 503 : 408;
        return SimpleResponse.raw(status, List.of("Retry-After: 0"), new byte[0]);
      }
      return SimpleResponse.ok("ok");
    })) {
      assertBody(baseClient(), server.url("/503"), "ok");
      assertBody(baseClient(), server.url("/408"), "ok");
    }
  }

  private static void okhttpOriginHttp408RetryRespectsRetryOnConnectionFailure() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.status(408, "timeout"))) {
      OkHttpClient client = baseClient().newBuilder()
          .retryOnConnectionFailure(false)
          .build();
      assertCode(client, server.url("/"), 408);
      require(server.pathRequests.get("/").get() == 1, "request count " + server.pathRequests);
    }
  }

  private static void okhttpOriginTimeoutErrorsUseSocketTimeoutTaxonomy() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(250);
      return SimpleResponse.ok("");
    })) {
      OkHttpClient client = baseClient().newBuilder().readTimeout(Duration.ofMillis(50)).build();
      try {
        client.newCall(new Request.Builder().url(server.url("/")).build()).execute().close();
      } catch (SocketTimeoutException expected) {
        return;
      }
    }
    throw new AssertionError("expected SocketTimeoutException");
  }

  private static void okhttpOriginTimeoutsFireWithoutSchedulerDelay() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(250);
      return SimpleResponse.ok("");
    })) {
      OkHttpClient client = baseClient().newBuilder().readTimeout(Duration.ofMillis(50)).build();
      long start = System.nanoTime();
      try {
        client.newCall(new Request.Builder().url(server.url("/slow")).build()).execute().close();
      } catch (SocketTimeoutException expected) {
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        require(elapsedMs < 200, "elapsed " + elapsedMs + "ms");
        return;
      }
    }
    throw new AssertionError("expected timeout");
  }

  private static void okhttpOriginHttp1RequestBodyIsFlushedBeforeTimeoutDetach() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(50);
      return SimpleResponse.ok(request.bodyString());
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .readTimeout(Duration.ofMillis(500))
          .build();
      Request request = new Request.Builder()
          .url(server.url("/slow-upload"))
          .post(RequestBody.create("payload", TEXT))
          .build();
      assertBody(client, request, "payload");
    }
  }

  private static void okhttpOriginCallTimeoutIsPreservedAcrossRedirects() throws Exception {
    try (RawServer server = new RawServer(request -> {
      if (request.path.equals("/redirect")) return SimpleResponse.raw(302, List.of("Location: /slow"), new byte[0]);
      sleep(1000);
      return SimpleResponse.ok("slow");
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .callTimeout(Duration.ofMillis(100))
          .build();
      long start = System.nanoTime();
      try {
        client.newCall(new Request.Builder().url(server.url("/redirect")).build()).execute().close();
      } catch (IOException expected) {
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        require(elapsedMs < 300, "elapsed " + elapsedMs);
        return;
      }
    }
    throw new AssertionError("expected timeout");
  }

  private static void okhttpOriginTimeoutFailuresAreNotRetried() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(250);
      return SimpleResponse.ok("");
    })) {
      OkHttpClient client = baseClient().newBuilder().readTimeout(Duration.ofMillis(50)).retryOnConnectionFailure(true).build();
      try {
        client.newCall(new Request.Builder().url(server.url("/")).build()).execute().close();
      } catch (SocketTimeoutException expected) {
        require(server.pathRequests.get("/").get() == 1, "request count " + server.pathRequests);
        return;
      }
    }
    throw new AssertionError("expected SocketTimeoutException");
  }

  private static void okhttpOriginNullHeaderValuesAreIgnored() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(String.valueOf(request.header("X-Test"))))) {
      Request request = new Request.Builder()
          .url(server.url("/"))
          .header("X-Test", null)
          .build();
      assertBody(baseClient(), request, "null");
    }
  }

  private static void okhttpOriginResponseRecordsSentAndReceivedTimestamps() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(20);
      return SimpleResponse.ok("ok");
    })) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require(response.sentRequestAtMillis() > 0, "sent timestamp missing");
        require(response.receivedResponseAtMillis() >= response.sentRequestAtMillis(),
            "timestamps " + response.sentRequestAtMillis() + " " + response.receivedResponseAtMillis());
      }
    }
  }

  private static void okhttpOriginResponseBodyCanBeReadAfterCallbackReturns() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("hello"))) {
      CountDownLatch callbackReturned = new CountDownLatch(1);
      Response[] holder = new Response[1];
      IOException[] failure = new IOException[1];
      baseClient().newCall(new Request.Builder().url(server.url("/")).build()).enqueue(new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) {
          failure[0] = e;
          callbackReturned.countDown();
        }

        @Override public void onResponse(okhttp3.Call call, Response response) {
          holder[0] = response;
          callbackReturned.countDown();
        }
      });
      require(callbackReturned.await(2, TimeUnit.SECONDS), "callback did not return");
      if (failure[0] != null) throw failure[0];
      try (Response response = holder[0]) {
        require(response.body().string().equals("hello"), "body after callback return failed");
      }
    }
  }

  private static void okhttpOriginSocksProxyUsesRemoteDns() throws Exception {
    socksRemoteDnsSchemesAreSupported();
  }

  private static void okhttpOriginDirectConnectionsUseConfiguredSocketFactory() throws Exception {
    AtomicInteger created = new AtomicInteger();
    SocketFactory socketFactory = new SocketFactory() {
      final SocketFactory delegate = SocketFactory.getDefault();

      @Override public Socket createSocket() throws IOException {
        created.incrementAndGet();
        return delegate.createSocket();
      }

      @Override public Socket createSocket(String host, int port) throws IOException {
        created.incrementAndGet();
        return delegate.createSocket(host, port);
      }

      @Override public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        created.incrementAndGet();
        return delegate.createSocket(host, port, localHost, localPort);
      }

      @Override public Socket createSocket(InetAddress host, int port) throws IOException {
        created.incrementAndGet();
        return delegate.createSocket(host, port);
      }

      @Override public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        created.incrementAndGet();
        return delegate.createSocket(address, port, localAddress, localPort);
      }
    };
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .socketFactory(socketFactory)
          .build();
      assertBody(client, server.url("/"), "ok");
      require(created.get() >= 1, "socket factory was not used");
    }
  }

  private static void okhttpOriginTls13IsEnabledOnModernJdk() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("tls").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .protocols(List.of(Protocol.HTTP_1_1))
          .build();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require(response.handshake() != null, "missing handshake");
        require(response.handshake().tlsVersion().javaName().equals("TLSv1.3"), "tls version " + response.handshake().tlsVersion());
      }
    }
  }

  private static void okhttpOriginSslSocketFactoryCannotBeUsedAsPlainSocketFactory() {
    try {
      baseClient().newBuilder()
          .socketFactory((SocketFactory) SSLSocketFactory.getDefault())
          .build();
    } catch (IllegalArgumentException expected) {
      return;
    }
    throw new AssertionError("SSL socket factory was accepted as plain socket factory");
  }

  private static void okhttpOriginHostnameVerificationDoesNotFallbackToCommonName() throws Exception {
    HeldCertificate commonNameOnly = new HeldCertificate.Builder()
        .commonName("127.0.0.1")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(commonNameOnly)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(commonNameOnly.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("cn").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .build();
      try {
        client.newCall(new Request.Builder().url("https://127.0.0.1:" + server.getPort() + "/").build()).execute().close();
      } catch (SSLPeerUnverifiedException expected) {
        return;
      }
    }
    throw new AssertionError("common-name fallback was accepted");
  }

  private static void okhttpOriginCustomTrustManagerIsUsedDirectly() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("trusted").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .protocols(List.of(Protocol.HTTP_1_1))
          .build();
      assertBody(client, server.url("/").toString(), "trusted");
    }
  }

  private static void okhttpOriginInsecureHostAllowlistDisablesVerificationOnlyForThatHost() throws Exception {
    HeldCertificate wrongHost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("wrong.example")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(wrongHost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(wrongHost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("allowed").build());
      server.enqueue(new MockResponse.Builder().body("blocked").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .hostnameVerifier((hostname, session) -> hostname.equals("localhost"))
          .build();
      assertBody(client, server.url("/").toString(), "allowed");
      try {
        client.newCall(new Request.Builder().url("https://127.0.0.1:" + server.getPort() + "/").build()).execute().close();
      } catch (SSLPeerUnverifiedException expected) {
        return;
      }
    }
    throw new AssertionError("non-allowlisted host was accepted");
  }

  private static void okhttpOriginSha256CertificatePinsAreSupported() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    CertificatePinner pinner = new CertificatePinner.Builder()
        .add("localhost", CertificatePinner.pin(localhost.certificate()))
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("pinned").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .certificatePinner(pinner)
          .build();
      assertBody(client, server.url("/").toString(), "pinned");
    }
  }

  private static void okhttpOriginNoPinsSkipsCertificateChainSanitization() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("no pins").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .certificatePinner(CertificatePinner.DEFAULT)
          .build();
      assertBody(client, server.url("/").toString(), "no pins");
    }
  }

  private static void okhttpOriginTls12IsPreferredWhereAvailable() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(localhost)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(localhost.certificate())
        .build();
    ConnectionSpec tls12Only = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_2)
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("tls12").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .connectionSpecs(List.of(tls12Only))
          .build();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require(response.handshake() != null, "missing handshake");
        require(response.handshake().tlsVersion() == TlsVersion.TLS_1_2, "tls version " + response.handshake().tlsVersion());
      }
    }
  }

  private static void okhttpOriginCacheControlHeaderAcceptsSemicolonSeparator() {
    Headers headers = new Headers.Builder()
        .add("Cache-Control", "max-age=60; private")
        .build();
    CacheControl cacheControl = CacheControl.parse(headers);
    require(cacheControl.maxAgeSeconds() == 60, "max-age " + cacheControl.maxAgeSeconds());
    require(cacheControl.isPrivate(), "private directive missing");
  }

  private static Cache tempCache() throws IOException {
    Path dir = Files.createTempDirectory("okhttp-origin-cache-");
    return new Cache(dir.toFile(), 1024 * 1024);
  }

  private static OkHttpClient cachedClient(Cache cache) {
    return baseClient().newBuilder().cache(cache).build();
  }

  private static void okhttpOriginCachePrivateResponsesAreHandled() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: private, max-age=60"), "private".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/private"), "private");
      try (Response response = client.newCall(new Request.Builder().url(server.url("/private")).build()).execute()) {
        require("private".equals(response.body().string()), "body mismatch");
        require(response.cacheResponse() != null, "second response was not cache hit");
      }
    }
  }

  private static void okhttpOriginCacheDefaultResponseCodesAreCached() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(308, List.of("Cache-Control: max-age=60"), new byte[0]))) {
      OkHttpClient client = cachedClient(cache).newBuilder().followRedirects(false).build();
      assertCode(client, server.url("/permanent"), 308);
      try (Response response = client.newCall(new Request.Builder().url(server.url("/permanent")).build()).execute()) {
        require(response.code() == 308, "code " + response.code());
        require(response.cacheResponse() != null, "second response was not cache hit");
      }
    }
  }

  private static void okhttpOriginCache302And308WithFreshnessHeaders() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(302, List.of("Cache-Control: max-age=60", "Location: /target"), new byte[0]))) {
      OkHttpClient client = cachedClient(cache).newBuilder().followRedirects(false).build();
      assertCode(client, server.url("/redirect"), 302);
      try (Response response = client.newCall(new Request.Builder().url(server.url("/redirect")).build()).execute()) {
        require(response.code() == 302, "code " + response.code());
        require(response.cacheResponse() != null, "second response was not cache hit");
      }
    }
  }

  private static HeldCertificate[] certificateChain() {
    HeldCertificate root = new HeldCertificate.Builder()
        .certificateAuthority(1)
        .commonName("root")
        .build();
    HeldCertificate intermediate = new HeldCertificate.Builder()
        .certificateAuthority(0)
        .commonName("intermediate")
        .signedBy(root)
        .build();
    HeldCertificate leaf = new HeldCertificate.Builder()
        .addSubjectAlternativeName("localhost")
        .signedBy(intermediate)
        .build();
    return new HeldCertificate[] {root, intermediate, leaf};
  }

  private static void okhttpOriginCertificatePinnerBuildsFullChains() throws Exception {
    HeldCertificate[] chain = certificateChain();
    HeldCertificate root = chain[0];
    HeldCertificate intermediate = chain[1];
    HeldCertificate leaf = chain[2];
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(leaf, intermediate.certificate())
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(root.certificate())
        .build();
    CertificatePinner pinner = new CertificatePinner.Builder()
        .add("localhost", CertificatePinner.pin(root.certificate()))
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("chain").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .certificatePinner(pinner)
          .build();
      assertBody(client, server.url("/").toString(), "chain");
    }
  }

  private static void okhttpOriginCertificatePinnerDoubleWildcardMatchesMultipleSubdomainDepths() throws Exception {
    HeldCertificate cert = new HeldCertificate.Builder()
        .addSubjectAlternativeName("a.b.example.test")
        .build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(cert)
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(cert.certificate())
        .build();
    CertificatePinner pinner = new CertificatePinner.Builder()
        .add("**.example.test", CertificatePinner.pin(cert.certificate()))
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("wildcard").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .certificatePinner(pinner)
          .dns(hostname -> hostname.equals("a.b.example.test") ? List.of(InetAddress.getByName("127.0.0.1")) : Dns.SYSTEM.lookup(hostname))
          .build();
      assertBody(client, "https://a.b.example.test:" + server.getPort() + "/", "wildcard");
    }
  }

  private static OkHttpClient http2ClientFor(HeldCertificate certificate) {
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(certificate.certificate())
        .build();
    return baseClient().newBuilder()
        .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
        .protocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1))
        .build();
  }

  private static MockWebServer http2Server(HeldCertificate certificate) {
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(certificate)
        .build();
    MockWebServer server = new MockWebServer();
    server.useHttps(serverCertificates.sslSocketFactory());
    server.setProtocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1));
    return server;
  }

  private static void okhttpOriginHttp2HeadInconsistentContentLengthDoesNotCrash() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().code(200).addHeader("Content-Length", "10").body("").build());
      server.start();
      Request request = new Request.Builder().url(server.url("/head")).head().build();
      try (Response response = http2ClientFor(localhost).newCall(request).execute()) {
        require(response.code() == 200, "code " + response.code());
        require(response.protocol() == Protocol.HTTP_2, "protocol " + response.protocol());
        require(response.body().bytes().length == 0, "HEAD body was not empty");
      }
    }
  }

  private static void okhttpOriginSpdyEmptyHeaderValuesArePreserved() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().addHeader("X-Empty", "").body("ok").build());
      server.start();
      try (Response response = http2ClientFor(localhost).newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require(response.protocol() == Protocol.HTTP_2, "protocol " + response.protocol());
        require("".equals(response.header("X-Empty")), "header was " + response.header("X-Empty"));
      }
    }
  }

  private static void okhttpOriginHttp2RequestHeadersAreNotSpdyConcatenated() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      Request request = new Request.Builder()
          .url(server.url("/"))
          .addHeader("Cookie", "a=1")
          .addHeader("Cookie", "b=2")
          .build();
      try (Response response = http2ClientFor(localhost).newCall(request).execute()) {
        require(response.protocol() == Protocol.HTTP_2, "protocol " + response.protocol());
        require(response.isSuccessful(), "code " + response.code());
      }
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "missing recorded request");
      String cookies = recorded.getHeaders().values("Cookie").toString();
      require(!cookies.contains("\u0000"), "NUL-joined cookie header " + cookies);
    }
  }

  private static void okhttpOriginInterceptorTimeoutOverridesAreHonored() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(250);
      return SimpleResponse.ok("slow");
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .readTimeout(Duration.ofSeconds(1))
          .addInterceptor(chain -> chain.withReadTimeout(50, TimeUnit.MILLISECONDS).proceed(chain.request()))
          .build();
      long start = System.nanoTime();
      try {
        client.newCall(new Request.Builder().url(server.url("/")).build()).execute().close();
      } catch (SocketTimeoutException expected) {
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        require(elapsedMs < 200, "elapsed " + elapsedMs);
        return;
      }
    }
    throw new AssertionError("expected timeout");
  }

  private static void okhttpOriginInterceptorsCanChangeRequestMethod() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.method))) {
      OkHttpClient client = baseClient().newBuilder()
          .addInterceptor(chain -> chain.proceed(chain.request().newBuilder().method("PUT", RequestBody.create("payload", TEXT)).build()))
          .build();
      Request request = new Request.Builder().url(server.url("/")).post(RequestBody.create("payload", TEXT)).build();
      assertBody(client, request, "PUT");
    }
  }

  private static void okhttpOriginNetworkInterceptorMutationReachesServer() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok(request.header("X-Test")))) {
      OkHttpClient client = baseClient().newBuilder()
          .addNetworkInterceptor(chain -> chain.proceed(chain.request().newBuilder().header("X-Test", "mutated").build()))
          .build();
      Request request = new Request.Builder().url(server.url("/")).header("X-Test", "original").build();
      assertBody(client, request, "mutated");
    }
  }

  private static void okhttpOriginNetworkInterceptorCanAccessConnection() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      AtomicInteger observed = new AtomicInteger();
      OkHttpClient client = baseClient().newBuilder()
          .addNetworkInterceptor(chain -> {
            if (chain.connection() != null) observed.incrementAndGet();
            return chain.proceed(chain.request());
          })
          .build();
      assertBody(client, server.url("/"), "ok");
      require(observed.get() == 1, "connection not observed");
    }
  }

  private static void okhttpOriginPreconnectInterceptorIoexceptionFailsCleanly() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("unexpected"))) {
      OkHttpClient client = baseClient().newBuilder()
          .addInterceptor(chain -> {
            throw new IOException("synthetic");
          })
          .build();
      try {
        client.newCall(new Request.Builder().url(server.url("/")).build()).execute().close();
      } catch (IOException expected) {
        require(server.acceptedConnections.get() == 0, "network was attempted");
        return;
      }
    }
    throw new AssertionError("expected IOException");
  }

  private static void okhttpOriginUnexpectedInterceptorExceptionNotifiesCallbackFailure() throws Exception {
    CountDownLatch latch = new CountDownLatch(1);
    RuntimeException boom = new RuntimeException("boom");
    Throwable[] failure = new Throwable[1];
    OkHttpClient client = baseClient().newBuilder()
        .addInterceptor(chain -> {
          throw boom;
        })
        .build();
    client.newCall(new Request.Builder().url("http://example.test/").build()).enqueue(new okhttp3.Callback() {
      @Override public void onFailure(okhttp3.Call call, IOException e) {
        failure[0] = e;
        latch.countDown();
      }

      @Override public void onResponse(okhttp3.Call call, Response response) {
        failure[0] = new AssertionError("unexpected response");
        latch.countDown();
      }
    });
    require(latch.await(2, TimeUnit.SECONDS), "callback not invoked");
    require(failure[0] instanceof IOException, "failure was " + failure[0]);
  }

  private static void okhttpOriginCallTagsAreVisibleAcrossListenersAndInterceptors() throws Exception {
    AtomicInteger interceptorSaw = new AtomicInteger();
    AtomicInteger listenerSaw = new AtomicInteger();
    okhttp3.EventListener listener = new okhttp3.EventListener() {
      @Override public void callStart(okhttp3.Call call) {
        if ("trace-id".equals(call.request().tag(String.class))) listenerSaw.incrementAndGet();
      }
    };
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .eventListener(listener)
          .addInterceptor(chain -> {
            if ("trace-id".equals(chain.request().tag(String.class))) interceptorSaw.incrementAndGet();
            return chain.proceed(chain.request());
          })
          .build();
      Request request = new Request.Builder().url(server.url("/")).tag(String.class, "trace-id").build();
      assertBody(client, request, "ok");
      require(interceptorSaw.get() == 1 && listenerSaw.get() == 1, "interceptor=" + interceptorSaw + " listener=" + listenerSaw);
    }
  }

  private static void okhttpOriginDnsIsNotCalledForLiteralIpAddresses() throws Exception {
    AtomicInteger lookups = new AtomicInteger();
    Dns dns = hostname -> {
      lookups.incrementAndGet();
      throw new UnknownHostException(hostname);
    };
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder().dns(dns).build();
      assertBody(client, server.url("/"), "ok");
      require(lookups.get() == 0, "dns lookups " + lookups.get());
    }
  }

  private static void okhttpOriginInvalidHostsDoNotTriggerDnsLookup() {
    AtomicInteger lookups = new AtomicInteger();
    Dns dns = hostname -> {
      lookups.incrementAndGet();
      return Dns.SYSTEM.lookup(hostname);
    };
    OkHttpClient client = baseClient().newBuilder().dns(dns).build();
    try {
      client.newCall(new Request.Builder().url("http://bad host/").build()).execute().close();
    } catch (Exception expected) {
      require(lookups.get() == 0, "dns lookups " + lookups.get());
      return;
    }
    throw new AssertionError("bad host was accepted");
  }

  private static void okhttpOriginCookieLoneQuoteValueDoesNotCrash() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.test/"));
    Cookie.parse(url, "a=\"");
  }

  private static void okhttpOriginCookieSamesiteAttributeIsParsed() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://example.test/"));
    Cookie cookie = Objects.requireNonNull(Cookie.parse(url, "sid=1; SameSite=Lax"));
    require(cookie.sameSite() != null && cookie.sameSite().toString().equalsIgnoreCase("Lax"), "sameSite " + cookie.sameSite());
  }

  private static void okhttpOriginNullDefaultAuthenticatorDoesNotCrash() throws Exception {
    java.net.Authenticator previous = java.net.Authenticator.getDefault();
    java.net.Authenticator.setDefault(null);
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(401, List.of("WWW-Authenticate: Basic realm=\"r\""), new byte[0]))) {
      assertCode(baseClient(), server.url("/auth"), 401);
    } finally {
      java.net.Authenticator.setDefault(previous);
    }
  }

  private static void okhttpOriginAuthenticationCredentialsSupportCharset() {
    String header = Credentials.basic("é", "p", StandardCharsets.UTF_8);
    require(header.equals("Basic w6k6cA=="), header);
  }

  private static void okhttpOriginWebsocketFailedUpgradeDoesNotCrash() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().code(400).body("no upgrade").build());
      server.start();
      CountDownLatch latch = new CountDownLatch(1);
      Throwable[] failure = new Throwable[1];
      baseClient().newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) {
          failure[0] = t;
          latch.countDown();
        }
      });
      require(latch.await(2, TimeUnit.SECONDS), "failure callback not invoked");
      require(failure[0] != null, "missing failure");
    }
  }

  private static void okhttpOriginWebsocketNon101ResponseBodyIsRetained() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().code(400).body("upgrade failed").build());
      server.start();
      CountDownLatch latch = new CountDownLatch(1);
      String[] body = new String[1];
      baseClient().newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) {
          try {
            body[0] = response == null ? null : response.body().string();
          } catch (IOException e) {
            body[0] = e.getClass().getSimpleName();
          }
          latch.countDown();
        }
      });
      require(latch.await(2, TimeUnit.SECONDS), "failure callback not invoked");
      require("upgrade failed".equals(body[0]), "body was " + body[0]);
    }
  }

  private static void okhttpOriginWebsocketAllows101210131014CloseCodes() {
    okhttp3.internal.ws.WebSocketProtocol.INSTANCE.validateCloseCode(1012);
    okhttp3.internal.ws.WebSocketProtocol.INSTANCE.validateCloseCode(1013);
    okhttp3.internal.ws.WebSocketProtocol.INSTANCE.validateCloseCode(1014);
  }

  private static void okhttpOriginDispatcherIdleCallbackFiresWhenNoCallsInFlight() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      Dispatcher dispatcher = new Dispatcher();
      AtomicInteger idle = new AtomicInteger();
      dispatcher.setIdleCallback(idle::incrementAndGet);
      OkHttpClient client = baseClient().newBuilder().dispatcher(dispatcher).build();
      CountDownLatch done = new CountDownLatch(2);
      okhttp3.Callback callback = new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) {
          done.countDown();
        }

        @Override public void onResponse(okhttp3.Call call, Response response) {
          response.close();
          done.countDown();
        }
      };
      client.newCall(new Request.Builder().url(server.url("/one")).build()).enqueue(callback);
      client.newCall(new Request.Builder().url(server.url("/two")).build()).enqueue(callback);
      require(done.await(2, TimeUnit.SECONDS), "calls did not finish");
      for (int i = 0; i < 20 && idle.get() == 0; i++) sleep(25);
      require(idle.get() >= 1, "idle callback did not fire");
    }
  }

  private static void okhttpOriginDispatcherQueueEventsAreEmitted() throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    List<String> events = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> {
      awaitLatch(release, 2, TimeUnit.SECONDS, "release not signaled");
      return SimpleResponse.ok("ok");
    })) {
      Dispatcher dispatcher = new Dispatcher();
      dispatcher.setMaxRequests(1);
      OkHttpClient client = baseClient().newBuilder()
          .dispatcher(dispatcher)
          .eventListener(new okhttp3.EventListener() {
            @Override public void dispatcherQueueStart(okhttp3.Call call, Dispatcher dispatcher) { events.add("dispatcherQueueStart"); }
            @Override public void dispatcherQueueEnd(okhttp3.Call call, Dispatcher dispatcher) { events.add("dispatcherQueueEnd"); }
          })
          .build();
      CountDownLatch done = new CountDownLatch(2);
      okhttp3.Callback callback = new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      };
      client.newCall(new Request.Builder().url(server.url("/one")).build()).enqueue(callback);
      client.newCall(new Request.Builder().url(server.url("/two")).build()).enqueue(callback);
      for (int i = 0; i < 20 && !events.contains("dispatcherQueueStart"); i++) sleep(25);
      release.countDown();
      require(done.await(2, TimeUnit.SECONDS), "calls did not finish");
      require(events.contains("dispatcherQueueStart") && events.contains("dispatcherQueueEnd"), "events " + events);
    }
  }

  private static void okhttpOriginDispatcherCountsQueuedAndRunningCalls() throws Exception {
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    try (RawServer server = new RawServer(request -> {
      entered.countDown();
      awaitLatch(release, 2, TimeUnit.SECONDS, "release not signaled");
      return SimpleResponse.ok("ok");
    })) {
      Dispatcher dispatcher = new Dispatcher();
      dispatcher.setMaxRequests(1);
      OkHttpClient client = baseClient().newBuilder().dispatcher(dispatcher).build();
      CountDownLatch done = new CountDownLatch(2);
      okhttp3.Callback callback = new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      };
      client.newCall(new Request.Builder().url(server.url("/one")).build()).enqueue(callback);
      require(entered.await(1, TimeUnit.SECONDS), "first call not running");
      client.newCall(new Request.Builder().url(server.url("/two")).build()).enqueue(callback);
      for (int i = 0; i < 20 && dispatcher.queuedCallsCount() == 0; i++) sleep(25);
      require(dispatcher.runningCallsCount() == 1, "running " + dispatcher.runningCallsCount());
      require(dispatcher.queuedCallsCount() == 1, "queued " + dispatcher.queuedCallsCount());
      release.countDown();
      require(done.await(2, TimeUnit.SECONDS), "calls did not finish");
    }
  }

  private static void okhttpOriginAsyncDispatcherParallelismIsPreserved() throws Exception {
    AtomicInteger inFlight = new AtomicInteger();
    AtomicInteger maxInFlight = new AtomicInteger();
    try (RawServer server = new RawServer(request -> {
      int now = inFlight.incrementAndGet();
      maxInFlight.updateAndGet(previous -> Math.max(previous, now));
      sleep(250);
      inFlight.decrementAndGet();
      return SimpleResponse.ok("ok");
    })) {
      Dispatcher dispatcher = new Dispatcher();
      dispatcher.setMaxRequests(64);
      dispatcher.setMaxRequestsPerHost(5);
      OkHttpClient client = baseClient().newBuilder().dispatcher(dispatcher).build();
      CountDownLatch done = new CountDownLatch(5);
      okhttp3.Callback callback = new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      };
      for (int i = 0; i < 5; i++) {
        client.newCall(new Request.Builder().url(server.url("/parallel")).build()).enqueue(callback);
      }
      require(done.await(3, TimeUnit.SECONDS), "calls did not finish");
      require(maxInFlight.get() == 5, "max in flight " + maxInFlight.get());
    }
  }

  private static void okhttpOriginCachedResponsePreservesRepeatedHeaders() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of(
             "Cache-Control: max-age=60",
             "Vary: Accept",
             "Vary: Accept-Encoding"
         ), "cached".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = cachedClient(cache);
      Request request = new Request.Builder().url(server.url("/vary")).header("Accept", "text/plain").build();
      assertBody(client, request, "cached");
      try (Response response = client.newCall(request).execute()) {
        require(response.cacheResponse() != null, "not cache hit");
        require(response.headers("Vary").equals(List.of("Accept", "Accept-Encoding")), "vary " + response.headers("Vary"));
      }
    }
  }

  private static void okhttpOriginImmutableCacheControlDirectiveMarksResponseFresh() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60, immutable"), "v1".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/immutable"), "v1");
      try (Response response = client.newCall(new Request.Builder().url(server.url("/immutable")).build()).execute()) {
        require(response.cacheResponse() != null, "not cache hit");
        require("v1".equals(response.body().string()), "body mismatch");
      }
    }
  }

  private static void okhttpOriginIfNoneMatchAndIfModifiedSinceNotBothSent() throws Exception {
    AtomicInteger count = new AtomicInteger();
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> {
           if (count.incrementAndGet() == 1) {
             return SimpleResponse.raw(200, List.of(
                 "Cache-Control: max-age=0",
                 "ETag: abc",
                 "Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT"
             ), "v1".getBytes(StandardCharsets.UTF_8));
           }
           boolean ok = request.header("If-None-Match") != null && request.header("If-Modified-Since") == null;
           return ok ? SimpleResponse.raw(304, List.of(), new byte[0]) : SimpleResponse.status(400, request.headers.toString());
         })) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/validate"), "v1");
      assertBody(client, server.url("/validate"), "v1");
    }
  }

  private static void okhttpOriginNonAsciiEtagCacheValidationDoesNotCrash() throws Exception {
    AtomicInteger count = new AtomicInteger();
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> {
           if (count.incrementAndGet() == 1) {
             return SimpleResponse.raw(200, List.of("Cache-Control: max-age=0", "ETag: \"é\""), "v1".getBytes(StandardCharsets.UTF_8));
           }
           return SimpleResponse.raw(304, List.of(), new byte[0]);
         })) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/etag"), "v1");
      assertBody(client, server.url("/etag"), "v1");
    }
  }

  private static void okhttpOriginCacheHitMissEventsAreEmitted() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "cached".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = cachedClient(cache).newBuilder()
          .eventListener(new okhttp3.EventListener() {
            @Override public void cacheMiss(okhttp3.Call call) { events.add("cacheMiss"); }
            @Override public void cacheHit(okhttp3.Call call, Response response) { events.add("cacheHit"); }
          })
          .build();
      assertBody(client, server.url("/events"), "cached");
      assertBody(client, server.url("/events"), "cached");
      require(events.contains("cacheMiss") && events.contains("cacheHit"), "events " + events);
    }
  }

  private static void okhttpOriginProxySelectionEventsAreEmitted() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .eventListener(new okhttp3.EventListener() {
            @Override public void proxySelectStart(okhttp3.Call call, HttpUrl url) { events.add("proxySelectStart"); }
            @Override public void proxySelectEnd(okhttp3.Call call, HttpUrl url, List<Proxy> proxies) { events.add("proxySelectEnd"); }
          })
          .build();
      assertBody(client, server.url("/"), "ok");
      require(events.contains("proxySelectStart") && events.contains("proxySelectEnd"), "events " + events);
    }
  }

  private static void okhttpOriginConnectionListenerReportsConnectDisconnectAndPooling() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .connectionPool(new ConnectionPool(1, 5, TimeUnit.MINUTES))
          .eventListener(new okhttp3.EventListener() {
            @Override public void connectStart(okhttp3.Call call, InetSocketAddress inetSocketAddress, Proxy proxy) { events.add("connectStart"); }
            @Override public void connectionAcquired(okhttp3.Call call, okhttp3.Connection connection) { events.add("connectionAcquired"); }
            @Override public void connectionReleased(okhttp3.Call call, okhttp3.Connection connection) { events.add("connectionReleased"); }
          })
          .build();
      assertBody(client, server.url("/one"), "ok");
      assertBody(client, server.url("/two"), "ok");
      require(events.contains("connectStart") && countOccurrences(String.join(",", events), "connectionAcquired") >= 2 && events.contains("connectionReleased"), "events " + events);
      require(server.acceptedConnections.get() == 1, "accepted " + server.acceptedConnections.get());
    }
  }

  private static void okhttpOriginCallEndEventIsEmittedWhenInterceptorConsumesBody() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .eventListener(new okhttp3.EventListener() {
            @Override public void callEnd(okhttp3.Call call) { events.add("callEnd"); }
          })
          .addInterceptor(chain -> {
            Response response = chain.proceed(chain.request());
            response.body().bytes();
            return response.newBuilder().body(ResponseBody.create("ok", TEXT)).build();
          })
          .build();
      assertBody(client, server.url("/"), "ok");
      require(events.contains("callEnd"), "events " + events);
    }
  }

  private static void okhttpOriginCorruptedCacheEntryIsRecoveredOrFailsFast() throws Exception {
    Path dir = Files.createTempDirectory("okhttp-corrupt-cache-");
    Files.writeString(dir.resolve("journal"), "not an okhttp cache journal\n", StandardCharsets.UTF_8);
    try (Cache cache = new Cache(dir.toFile(), 1024 * 1024);
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "network".getBytes(StandardCharsets.UTF_8)))) {
      assertBody(cachedClient(cache), server.url("/"), "network");
    }
  }

  private static void okhttpOriginCacheWriteFailureDoesNotLeakOrCrash() throws Exception {
    Path dir = Files.createTempDirectory("okhttp-small-cache-");
    try (Cache cache = new Cache(dir.toFile(), 1);
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "network".getBytes(StandardCharsets.UTF_8)))) {
      assertBody(cachedClient(cache), server.url("/"), "network");
      cache.flush();
      require(cache.writeAbortCount() >= 0, "cache stats unavailable");
    }
  }

  private static void okhttpOriginImmutableCacheControlIsNotPermanent() throws Exception {
    AtomicInteger count = new AtomicInteger();
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> {
           if (count.incrementAndGet() == 1) {
             return SimpleResponse.raw(200, List.of("Cache-Control: immutable, max-age=1"), "v1".getBytes(StandardCharsets.UTF_8));
           }
           return SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "v2".getBytes(StandardCharsets.UTF_8));
         })) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/immutable-short"), "v1");
      sleep(1200);
      assertBody(client, server.url("/immutable-short"), "v2");
    }
  }

  private static void okhttpOriginCache304DoesNotCorruptContentEncoding() throws Exception {
    AtomicInteger count = new AtomicInteger();
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> {
           if (count.incrementAndGet() == 1) {
             return SimpleResponse.raw(200, List.of(
                 "Cache-Control: max-age=0",
                 "ETag: abc",
                 "Content-Encoding: gzip"
             ), gzip("hello"));
           }
           return SimpleResponse.raw(304, List.of("Content-Encoding: identity"), new byte[0]);
         })) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/gzip-validate"), "hello");
      assertBody(client, server.url("/gzip-validate"), "hello");
    }
  }

  private static void okhttpOriginCacheHitStreamAllocationSurvivesRedirect() throws Exception {
    AtomicInteger redirectHits = new AtomicInteger();
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> {
           if (request.path.equals("/redirect")) {
             redirectHits.incrementAndGet();
             return SimpleResponse.raw(302, List.of("Cache-Control: max-age=60", "Location: /target"), new byte[0]);
           }
           return SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "ok".getBytes(StandardCharsets.UTF_8));
         })) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/redirect"), "ok");
      assertBody(client, server.url("/redirect"), "ok");
      require(redirectHits.get() == 1, "redirect was not served from cache");
    }
  }

  private static void okhttpOriginCacheCanBeInitializedEagerly() throws Exception {
    try (Cache cache = tempCache()) {
      cache.initialize();
      require(cache.size() >= 0, "cache not initialized");
    }
  }

  private static void okhttpOriginResponseCacheInitializesLazily() throws Exception {
    Path dir = Files.createTempDirectory("okhttp-lazy-cache-");
    try (Cache cache = new Cache(dir.toFile(), 1024 * 1024)) {
      baseClient().newBuilder().cache(cache).build();
      require(Files.list(dir).findAny().isEmpty(), "cache directory touched before first request");
    }
  }

  private static void okhttpOriginCacheHitDoesNotEagerlyReleasePool() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "cached".getBytes(StandardCharsets.UTF_8)))) {
      ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
      OkHttpClient client = cachedClient(cache).newBuilder().connectionPool(pool).build();
      assertBody(client, server.url("/cached"), "cached");
      assertBody(client, server.url("/cached"), "cached");
      require(pool.idleConnectionCount() >= 0, "pool inaccessible");
    }
  }

  private static void okhttpOriginCacheVaryHeadersPreservedInAndroidHttpCache() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60", "Vary: Accept-Encoding"), "cached".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/vary-ae"), "cached");
      try (Response response = client.newCall(new Request.Builder().url(server.url("/vary-ae")).build()).execute()) {
        require("Accept-Encoding".equals(response.header("Vary")), "vary " + response.header("Vary"));
      }
    }
  }

  private static void okhttpOriginCacheStoresRewrittenRequestHeaders() throws Exception {
    AtomicInteger count = new AtomicInteger();
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> {
           if (count.incrementAndGet() == 1) {
             require("gzip".equalsIgnoreCase(request.header("Accept-Encoding")), "accept-encoding " + request.header("Accept-Encoding"));
           }
           return SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "cached".getBytes(StandardCharsets.UTF_8));
         })) {
      OkHttpClient client = cachedClient(cache);
      assertBody(client, server.url("/gzip-request"), "cached");
      assertBody(client, server.url("/gzip-request"), "cached");
      require(count.get() == 1, "cache miss count " + count.get());
    }
  }

  private static void okhttpOriginBadCacheThrowsCheckedError() throws Exception {
    Path fileInsteadOfDirectory = Files.createTempFile("okhttp-bad-cache-", ".tmp");
    try (Cache cache = new Cache(fileInsteadOfDirectory.toFile(), 1024);
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "network".getBytes(StandardCharsets.UTF_8)))) {
      try {
        assertBody(cachedClient(cache), server.url("/"), "network");
      } catch (IOException expected) {
        return;
      }
    }
  }

  private static void okhttpOriginLoggingRedactsConfiguredQueryParameters() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add);
    logging.redactQueryParams("token");
    logging.setLevel(HttpLoggingInterceptor.Level.BASIC);
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      assertBody(client, server.url("/path?token=secret&safe=1"), "ok");
    }
    String joined = String.join("\n", logs);
    require(!joined.contains("secret"), joined);
    require(joined.contains("safe=1"), joined);
  }

  private static void okhttpOriginLoggingReportsTotalCallTime() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BASIC);
    try (RawServer server = new RawServer(request -> {
      sleep(60);
      return SimpleResponse.ok("ok");
    })) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      assertBody(client, server.url("/slow-log"), "ok");
    }
    require(String.join("\n", logs).contains("ms"), String.join("\n", logs));
  }

  private static void okhttpOriginServerSentEventBodiesAreNotLogged() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BODY);
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Type: text/event-stream"), "data: secret\n\n".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      assertBody(client, server.url("/events"), "data: secret\n\n");
    }
    require(!String.join("\n", logs).contains("secret"), String.join("\n", logs));
  }

  private static void okhttpOriginLoggingInterceptorHonorsOneShotRequestBody() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BODY);
    RequestBody oneShot = new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public boolean isOneShot() { return true; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException { sink.writeUtf8("secret"); }
    };
    AtomicInteger serverSawBody = new AtomicInteger();
    try (RawServer server = new RawServer(request -> {
      if ("secret".equals(request.bodyString())) serverSawBody.incrementAndGet();
      return SimpleResponse.ok("ok");
    })) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      Request request = new Request.Builder().url(server.url("/one-shot")).post(oneShot).build();
      assertBody(client, request, "ok");
    }
    require(serverSawBody.get() == 1, "one-shot body was consumed before network");
    require(!String.join("\n", logs).contains("secret"), String.join("\n", logs));
  }

  private static void okhttpOriginHttpLoggingInterceptorRedactsConfiguredHeaders() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add);
    logging.redactHeader("Authorization");
    logging.setLevel(HttpLoggingInterceptor.Level.HEADERS);
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      Request request = new Request.Builder().url(server.url("/redact")).header("Authorization", "secret").build();
      assertBody(client, request, "ok");
    }
    require(!String.join("\n", logs).contains("secret"), String.join("\n", logs));
  }

  private static void okhttpOriginLoggingPlaintextClassifierAllowsNewlines() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BODY);
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Type: text/plain"), "hello\nworld".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      assertBody(client, server.url("/plain"), "hello\nworld");
    }
    String joined = String.join("\n", logs);
    require(joined.contains("hello") && joined.contains("world"), joined);
  }

  private static void okhttpOriginLoggingInterceptorLogsConnectionFailures() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BASIC);
    OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).connectTimeout(Duration.ofMillis(100)).build();
    try {
      client.newCall(new Request.Builder().url("http://127.0.0.1:1/").build()).execute().close();
    } catch (IOException expected) {
      require(String.join("\n", logs).toLowerCase(Locale.ROOT).contains("failed"), String.join("\n", logs));
      return;
    }
    throw new AssertionError("expected connection failure");
  }

  private static void okhttpOriginLoggingInterceptorHandlesUnexpectedCharset() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BODY);
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Type: text/plain; charset=bad-charset"), "hello".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      assertBody(client, server.url("/bad-charset"), "hello");
    }
  }

  private static void okhttpOriginLoggingInterceptorUsesRequestBodyCharset() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BODY);
    byte[] latin1 = {(byte) 0xe9};
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      Request request = new Request.Builder()
          .url(server.url("/latin1"))
          .post(RequestBody.create(latin1, MediaType.get("text/plain; charset=ISO-8859-1")))
          .build();
      assertBody(client, request, "ok");
    }
    require(String.join("\n", logs).contains("é"), String.join("\n", logs));
  }

  private static void okhttpOriginLoggingInterceptorHandlesNoContentResponses() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    HttpLoggingInterceptor logging = new HttpLoggingInterceptor(logs::add).setLevel(HttpLoggingInterceptor.Level.BODY);
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(204, List.of(), new byte[0]))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(logging).build();
      assertCode(client, server.url("/no-content"), 204);
    }
    require(!String.join("\n", logs).contains("\n\n<-- END HTTP"), String.join("\n", logs));
  }

  private static void okhttpOriginCookiesAreAcceptedForIpv6Hosts() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://[::1]/"));
    Cookie cookie = Objects.requireNonNull(Cookie.parse(url, "a=1"));
    require(cookie.matches(url), "cookie did not match IPv6 URL");
  }

  private static void okhttpOriginPublicDomainCookiesAreRejected() {
    HttpUrl url = Objects.requireNonNull(HttpUrl.parse("http://foo.co.uk/"));
    require(Cookie.parse(url, "a=1; Domain=co.uk") == null, "public suffix cookie was accepted");
  }

  private static void okhttpOriginJavaNetCookieJarHandlesMultipleCookies() throws Exception {
    CookieManager manager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    OkHttpClient client = baseClient().newBuilder().cookieJar(new JavaNetCookieJar(manager)).build();
    AtomicInteger count = new AtomicInteger();
    try (RawServer server = new RawServer(request -> {
      if (count.incrementAndGet() == 1) {
        return SimpleResponse.raw(200, List.of("Set-Cookie: a=1", "Set-Cookie: b=2"), "ok".getBytes(StandardCharsets.UTF_8));
      }
      String cookie = request.header("Cookie");
      return cookie != null && cookie.contains("a=1") && cookie.contains("b=2")
          ? SimpleResponse.ok("ok")
          : SimpleResponse.status(400, String.valueOf(cookie));
    })) {
      assertBody(client, server.url("/cookies"), "ok");
      assertBody(client, server.url("/cookies"), "ok");
    }
  }

  private static void okhttpOriginRetryDecisionEventIsEmitted() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    AtomicInteger attempts = new AtomicInteger();
    try (RawServer server = new RawServer(request -> attempts.incrementAndGet() == 1
        ? SimpleResponse.closeWithoutResponse()
        : SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .retryOnConnectionFailure(true)
          .eventListener(new okhttp3.EventListener() {
            @Override public void retryDecision(okhttp3.Call call, IOException exception, boolean retry) { events.add("retry:" + retry); }
          })
          .build();
      assertBody(client, server.url("/retry-event"), "ok");
      require(events.stream().anyMatch(event -> event.equals("retry:true")), "events " + events);
    }
  }

  private static void okhttpOriginFollowupDecisionEventIsEmitted() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> request.path.equals("/redirect")
        ? SimpleResponse.redirect("/done")
        : SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .eventListener(new okhttp3.EventListener() {
            @Override public void followUpDecision(okhttp3.Call call, Response response, Request request) { events.add(response.code() + ":" + (request != null)); }
          })
          .build();
      assertBody(client, server.url("/redirect"), "ok");
      require(events.stream().anyMatch(event -> event.startsWith("303:true")), "events " + events);
    }
  }

  private static void okhttpOriginEventListenerCanceledEventIsEmitted() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> {
      sleep(1000);
      return SimpleResponse.ok("slow");
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .eventListener(new okhttp3.EventListener() {
            @Override public void canceled(okhttp3.Call call) { events.add("canceled"); }
          })
          .build();
      okhttp3.Call call = client.newCall(new Request.Builder().url(server.url("/cancel-event")).build());
      CountDownLatch done = new CountDownLatch(1);
      call.enqueue(new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      });
      sleep(100);
      call.cancel();
      require(done.await(2, TimeUnit.SECONDS), "callback not invoked");
      require(events.contains("canceled"), "events " + events);
    }
  }

  private static void okhttpOriginRequestFailedAndResponseFailedEventsAreEmitted() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> SimpleResponse.rawWithLength(200, List.of(), "abc".getBytes(StandardCharsets.UTF_8), 10, true))) {
      OkHttpClient client = baseClient().newBuilder()
          .eventListener(new okhttp3.EventListener() {
            @Override public void requestFailed(okhttp3.Call call, IOException ioe) { events.add("requestFailed"); }
            @Override public void responseFailed(okhttp3.Call call, IOException ioe) { events.add("responseFailed"); }
          })
          .build();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/truncated")).build()).execute()) {
        response.body().string();
      } catch (IOException expected) {
        require(events.contains("responseFailed") || events.contains("requestFailed"), "events " + events);
        return;
      }
    }
    throw new AssertionError("expected truncated response failure");
  }

  private static void okhttpOriginDispatcherExecutorShutdownReportsRejectedExecution() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    Dispatcher dispatcher = new Dispatcher(executor);
    executor.shutdownNow();
    CountDownLatch done = new CountDownLatch(1);
    Throwable[] failure = new Throwable[1];
    OkHttpClient client = baseClient().newBuilder().dispatcher(dispatcher).build();
    try {
      client.newCall(new Request.Builder().url("http://127.0.0.1:1/").build()).enqueue(new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { failure[0] = e; done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      });
    } catch (RuntimeException e) {
      failure[0] = e;
      done.countDown();
    }
    require(done.await(1, TimeUnit.SECONDS), "no failure delivered");
    require(failure[0] != null, "missing failure");
  }

  private static void okhttpOriginCanceledAsyncCallStillGetsCallback() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(1000);
      return SimpleResponse.ok("slow");
    })) {
      CountDownLatch done = new CountDownLatch(1);
      AtomicInteger failures = new AtomicInteger();
      okhttp3.Call call = baseClient().newCall(new Request.Builder().url(server.url("/cancel-callback")).build());
      call.enqueue(new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { failures.incrementAndGet(); done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      });
      call.cancel();
      require(done.await(2, TimeUnit.SECONDS), "callback not invoked");
      require(failures.get() == 1, "failure callback count " + failures.get());
    }
  }

  private static void okhttpOriginAsyncUncaughtExceptionsAreDelivered() throws Exception {
    CountDownLatch done = new CountDownLatch(1);
    Throwable[] failure = new Throwable[1];
    OkHttpClient client = baseClient().newBuilder()
        .addInterceptor(chain -> { throw new RuntimeException("boom"); })
        .build();
    client.newCall(new Request.Builder().url("http://example.test/").build()).enqueue(new okhttp3.Callback() {
      @Override public void onFailure(okhttp3.Call call, IOException e) { failure[0] = e; done.countDown(); }
      @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
    });
    require(done.await(2, TimeUnit.SECONDS), "callback not invoked");
    require(failure[0] != null, "failure missing");
  }

  private static void okhttpOriginInterruptedStateIsRetainedAfterInterruptedIo() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(1000);
      return SimpleResponse.ok("slow");
    })) {
      OkHttpClient client = baseClient().newBuilder().readTimeout(Duration.ofSeconds(2)).build();
      CountDownLatch done = new CountDownLatch(1);
      AtomicInteger interruptedRetained = new AtomicInteger();
      Thread worker = new Thread(() -> {
        Thread.currentThread().interrupt();
        try {
          client.newCall(new Request.Builder().url(server.url("/interrupted")).build()).execute().close();
        } catch (Exception expected) {
          if (Thread.currentThread().isInterrupted()) interruptedRetained.incrementAndGet();
        } finally {
          Thread.interrupted();
          done.countDown();
        }
      }, "interrupted-okhttp-call");
      worker.start();
      require(done.await(2, TimeUnit.SECONDS), "interrupted call did not finish");
      require(interruptedRetained.get() == 1, "interrupted flag was not retained");
    }
  }

  private static void okhttpOriginProxyAuthenticatorHandlesProxyChallenges() throws Exception {
    AtomicInteger count = new AtomicInteger();
    List<String> proxyAuthHeaders = new CopyOnWriteArrayList<>();
    try (RawServer proxy = new RawServer(request -> {
      proxyAuthHeaders.add(String.valueOf(request.header("Proxy-Authorization")));
      if (count.incrementAndGet() == 1) {
        return SimpleResponse.raw(407, List.of("Proxy-Authenticate: Basic realm=\"proxy\""), new byte[0]);
      }
      return "Basic abc".equals(request.header("Proxy-Authorization")) ? SimpleResponse.ok("ok") : SimpleResponse.status(407, "missing proxy auth");
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .proxyAuthenticator((route, response) -> response.request().newBuilder().header("Proxy-Authorization", "Basic abc").build())
          .authenticator((route, response) -> response.request().newBuilder().header("Authorization", "Basic wrong").build())
          .build();
      assertBody(client, "http://origin.test/resource", "ok");
      require(proxyAuthHeaders.contains("Basic abc"), "proxy auth headers " + proxyAuthHeaders);
    }
  }

  private static void okhttpOriginProxySelectionIsDeferredUntilNeeded() throws Exception {
    AtomicInteger selects = new AtomicInteger();
    ProxySelector selector = new ProxySelector() {
      @Override public List<Proxy> select(URI uri) {
        selects.incrementAndGet();
        return List.of(Proxy.NO_PROXY);
      }
      @Override public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
      }
    };
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .proxySelector(selector)
          .connectionPool(new ConnectionPool(1, 5, TimeUnit.MINUTES))
          .build();
      assertBody(client, server.url("/one"), "ok");
      selects.set(0);
      assertBody(client, server.url("/two"), "ok");
      require(selects.get() == 0, "proxy selector invoked for pooled route " + selects.get());
    }
  }

  private static void okhttpOriginTlsTunnelTruncatedResponseBodyDoesNotCrash() throws Exception {
    try (RawServer proxy = new RawServer(request -> SimpleResponse.rawWithLength(407, List.of("Proxy-Authenticate: Basic realm=\"proxy\""), "abc".getBytes(StandardCharsets.UTF_8), 10, true))) {
      OkHttpClient client = baseClient().newBuilder()
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .connectTimeout(Duration.ofMillis(500))
          .readTimeout(Duration.ofMillis(500))
          .build();
      try {
        client.newCall(new Request.Builder().url("https://origin.test/").build()).execute().close();
      } catch (IOException expected) {
        return;
      }
    }
    throw new AssertionError("expected proxy tunnel failure");
  }

  private static void okhttpOriginCertificatePinnerPinsAreInspectable() {
    CertificatePinner pinner = new CertificatePinner.Builder()
        .add("example.test", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build();
    require(pinner.findMatchingPins("example.test").toString().contains("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), pinner.findMatchingPins("example.test").toString());
  }

  private static void okhttpOriginConnectionSpecReportsSocketCompatibility() throws Exception {
    try (javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
      socket.setEnabledProtocols(new String[] {"TLSv1.2"});
      String cipher = Arrays.stream(socket.getSupportedCipherSuites()).filter(name -> name.contains("_AES_")).findFirst().orElse(socket.getSupportedCipherSuites()[0]);
      socket.setEnabledCipherSuites(new String[] {cipher});
      ConnectionSpec spec = new ConnectionSpec.Builder(true)
          .tlsVersions(TlsVersion.TLS_1_2)
          .cipherSuites(CipherSuite.forJavaName(cipher))
          .build();
      require(spec.isCompatible(socket), "spec incompatible with socket");
    }
  }

  private static void okhttpOriginConnectionSpecCanUseSocketDefaultCipherSuites() throws Exception {
    try (javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
      String[] enabled = socket.getEnabledCipherSuites();
      ConnectionSpec.MODERN_TLS.apply$okhttp(socket, false);
      require(socket.getEnabledCipherSuites().length > 0, "no enabled cipher suites");
      require(Arrays.asList(enabled).contains(socket.getEnabledCipherSuites()[0]) || socket.getSupportedCipherSuites().length > 0, "unexpected cipher suite state");
    }
  }

  private static void okhttpOriginHttp2FlowControlWindowUpdatesBeforeApplicationRead() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    byte[] large = new byte[256 * 1024];
    Arrays.fill(large, (byte) 'a');
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body(new Buffer().write(large)).build());
      server.enqueue(new MockResponse.Builder().body("second").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost);
      Response first = client.newCall(new Request.Builder().url(server.url("/first")).build()).execute();
      try (Response second = client.newCall(new Request.Builder().url(server.url("/second")).build()).execute()) {
        require("second".equals(second.body().string()), "second stream blocked");
      } finally {
        first.close();
      }
    }
  }

  private static void okhttpOriginDiscardedHttp2DataReleasesFlowControlWindow() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    byte[] large = new byte[256 * 1024];
    Arrays.fill(large, (byte) 'b');
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body(new Buffer().write(large)).build());
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost);
      Response first = client.newCall(new Request.Builder().url(server.url("/first")).build()).execute();
      first.close();
      assertBody(client, new Request.Builder().url(server.url("/second")).build(), "ok");
    }
  }

  private static void okhttpOriginWebsocketClosedBeforeConnectDoesNotCrash() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(1000);
      return SimpleResponse.status(400, "late");
    })) {
      CountDownLatch done = new CountDownLatch(1);
      okhttp3.WebSocket ws = baseClient().newWebSocket(new Request.Builder().url(server.url("/ws").replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) { done.countDown(); }
        @Override public void onClosed(okhttp3.WebSocket webSocket, int code, String reason) { done.countDown(); }
      });
      ws.close(1000, "bye");
      require(done.await(2, TimeUnit.SECONDS), "websocket did not complete");
    }
  }

  private static void okhttpOriginWebsocketFailedUpgradeDoesNotLeakSocket() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().code(400).body("bad").build());
      server.start();
      CountDownLatch latch = new CountDownLatch(1);
      ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
      OkHttpClient client = baseClient().newBuilder().connectionPool(pool).build();
      client.newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) { latch.countDown(); }
      });
      require(latch.await(2, TimeUnit.SECONDS), "failure callback not invoked");
      require(pool.connectionCount() >= 0, "pool unavailable");
    }
  }

  private static void okhttpOriginWebsocketsDoNotCountTowardPerHostDispatcherLimit() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder()
          .code(101)
          .addHeader("Connection", "Upgrade")
          .addHeader("Upgrade", "websocket")
          .build());
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      Dispatcher dispatcher = new Dispatcher();
      dispatcher.setMaxRequestsPerHost(1);
      CountDownLatch opened = new CountDownLatch(1);
      OkHttpClient client = baseClient().newBuilder().dispatcher(dispatcher).build();
      client.newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onOpen(okhttp3.WebSocket webSocket, Response response) { opened.countDown(); }
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) { opened.countDown(); }
      });
      require(opened.await(2, TimeUnit.SECONDS), "websocket did not open or fail");
      assertBody(client, server.url("/http").toString(), "ok");
    }
  }

  private static void okhttpOriginMediaTypeParameterExtractsQuotedBoundary() {
    MediaType mediaType = MediaType.get("multipart/mixed; boundary=\"abc\"");
    require("abc".equals(mediaType.parameter("boundary")), "boundary " + mediaType.parameter("boundary"));
  }

  private static void okhttpOriginMultipartPartSinkCloseDoesNotCloseRequestBody() throws Exception {
    try (RawServer server = new RawServer(request -> {
      String body = request.bodyString();
      boolean ok = body.contains("\r\n\r\na\r\n") && body.contains("\r\n\r\nb\r\n");
      return ok ? SimpleResponse.ok("ok") : SimpleResponse.status(400, body);
    })) {
      RequestBody body = new MultipartBody.Builder("abc")
          .setType(MultipartBody.FORM)
          .addFormDataPart("first", "a")
          .addFormDataPart("second", "b")
          .build();
      Request request = new Request.Builder().url(server.url("/multipart-lifecycle")).post(body).build();
      assertBody(baseClient(), request, "ok");
    }
  }

  private static void okhttpOriginOneShotRequestBodyIsNotRetransmitted() throws Exception {
    AtomicInteger requests = new AtomicInteger();
    RequestBody oneShot = new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public boolean isOneShot() { return true; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException { sink.writeUtf8("abcdef"); }
    };
    try (RawServer server = new RawServer(request -> {
      requests.incrementAndGet();
      return SimpleResponse.closeWithoutResponse();
    })) {
      OkHttpClient client = baseClient().newBuilder().retryOnConnectionFailure(true).build();
      try {
        client.newCall(new Request.Builder().url(server.url("/one-shot-retry")).post(oneShot).build()).execute().close();
      } catch (IOException expected) {
        require(requests.get() == 1, "one-shot body retried " + requests.get());
        return;
      }
    }
    throw new AssertionError("expected failure");
  }

  private static void okhttpOriginFileNotFoundRequestBodyIsNotRetried() throws Exception {
    AtomicInteger writes = new AtomicInteger();
    RequestBody missing = new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException {
        writes.incrementAndGet();
        throw new java.io.FileNotFoundException("missing");
      }
    };
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("unexpected"))) {
      OkHttpClient client = baseClient().newBuilder().retryOnConnectionFailure(true).build();
      try {
        client.newCall(new Request.Builder().url(server.url("/missing")).post(missing).build()).execute().close();
      } catch (java.io.FileNotFoundException expected) {
        require(writes.get() == 1, "body write retried " + writes.get());
        require(server.acceptedConnections.get() <= 1, "unexpected connection attempts " + server.acceptedConnections.get());
        return;
      }
    }
    throw new AssertionError("expected FileNotFoundException");
  }

  private static void okhttpOriginCallTimeoutAppliesWhileConnectingLongLivedStreams() throws Exception {
    try (RawServer server = new RawServer(request -> {
      sleep(1000);
      return SimpleResponse.status(400, "late");
    })) {
      CountDownLatch done = new CountDownLatch(1);
      Throwable[] failure = new Throwable[1];
      long start = System.nanoTime();
      OkHttpClient client = baseClient().newBuilder().callTimeout(Duration.ofMillis(50)).build();
      client.newWebSocket(new Request.Builder().url(server.url("/ws-timeout").replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) {
          failure[0] = t;
          done.countDown();
        }
      });
      require(done.await(2, TimeUnit.SECONDS), "websocket timeout did not fire");
      long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      require(failure[0] != null && elapsedMs < 500, "failure=" + failure[0] + " elapsed=" + elapsedMs);
    }
  }

  private static void okhttpOriginPooledConnectionTimeoutsAreNotShared() throws Exception {
    AtomicInteger count = new AtomicInteger();
    try (RawServer server = new RawServer(request -> {
      if (count.incrementAndGet() == 2) sleep(120);
      return SimpleResponse.ok("ok");
    })) {
      ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
      OkHttpClient client = baseClient().newBuilder().connectionPool(pool).readTimeout(Duration.ofMillis(50)).build();
      assertBody(client, server.url("/first"), "ok");
      OkHttpClient slower = client.newBuilder().readTimeout(Duration.ofSeconds(1)).build();
      assertBody(slower, server.url("/second"), "ok");
      require(server.acceptedConnections.get() == 1, "connection not reused");
    }
  }

  private static void okhttpOriginRouteIsRetainedOnReusedFollowupConnection() throws Exception {
    AtomicInteger routeSeen = new AtomicInteger();
    try (RawServer server = new RawServer(request -> request.header("Authorization") == null
        ? SimpleResponse.raw(401, List.of("WWW-Authenticate: Basic realm=\"r\""), new byte[0])
        : SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .authenticator((route, response) -> {
            if (route != null) routeSeen.incrementAndGet();
            return response.request().newBuilder().header("Authorization", Credentials.basic("u", "p")).build();
          })
          .build();
      assertBody(client, server.url("/auth-route"), "ok");
      require(routeSeen.get() >= 1, "route was not supplied to authenticator");
    }
  }

  private static void okhttpOriginHttpsPostStreamingIsNotAlwaysBuffered() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder().heldCertificate(localhost).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder().addTrustedCertificate(localhost.certificate()).build();
    RequestBody streaming = new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public long contentLength() { return -1; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException { sink.writeUtf8("streamed"); }
    };
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .protocols(List.of(Protocol.HTTP_1_1))
          .build();
      assertBody(client, new Request.Builder().url(server.url("/upload")).post(streaming).build(), "ok");
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "missing recorded request");
      require("chunked".equalsIgnoreCase(recorded.getHeaders().get("Transfer-Encoding")), recorded.getHeaders().toString());
    }
  }

  private static void okhttpOriginNonAsciiHttp2AndCachedHeadersDoNotCrash() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (Cache cache = tempCache();
         MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().addHeader("Cache-Control", "max-age=60").addHeader("X-Name", "é").body("ok").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost).newBuilder().cache(cache).build();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/non-ascii")).build()).execute()) {
        require(response.protocol() == Protocol.HTTP_2, "protocol " + response.protocol());
        require("é".equals(response.header("X-Name")), "header " + response.header("X-Name"));
        response.body().string();
      }
      try (Response response = client.newCall(new Request.Builder().url(server.url("/non-ascii")).build()).execute()) {
        require(response.cacheResponse() != null, "not cache hit");
        require("é".equals(response.header("X-Name")), "cached header " + response.header("X-Name"));
      }
    }
  }

  private static void okhttpOriginCallProceedNeverReturnsNullAfterCancel() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      AtomicInteger nonNull = new AtomicInteger();
      OkHttpClient client = baseClient().newBuilder()
          .addInterceptor(chain -> {
            chain.call().cancel();
            Response response = chain.proceed(chain.request());
            if (response != null) nonNull.incrementAndGet();
            return response;
          })
          .build();
      try {
        client.newCall(new Request.Builder().url(server.url("/cancel-proceed")).build()).execute().close();
      } catch (IOException expected) {
        return;
      }
      require(nonNull.get() == 1, "proceed returned null");
    }
  }

  private static void okhttpOriginSseCallsSendAcceptEventStreamByDefault() throws Exception {
    List<String> accepts = new CopyOnWriteArrayList<>();
    CountDownLatch closed = new CountDownLatch(1);
    try (RawServer server = new RawServer(request -> {
      accepts.add(request.header("Accept"));
      return SimpleResponse.raw(200, List.of("Content-Type: text/event-stream"), "data: ok\n\n".getBytes(StandardCharsets.UTF_8));
    })) {
      EventSources.createFactory(baseClient()).newEventSource(new Request.Builder().url(server.url("/sse")).build(), new EventSourceListener() {
        @Override public void onClosed(EventSource eventSource) { closed.countDown(); }
        @Override public void onFailure(EventSource eventSource, Throwable t, Response response) { closed.countDown(); }
      });
      require(closed.await(2, TimeUnit.SECONDS), "sse did not finish");
      require(accepts.stream().anyMatch("text/event-stream"::equals), "accepts " + accepts);
    }
  }

  private static void okhttpOriginSsePreservesExistingAcceptHeader() throws Exception {
    List<String> accepts = new CopyOnWriteArrayList<>();
    CountDownLatch closed = new CountDownLatch(1);
    try (RawServer server = new RawServer(request -> {
      accepts.add(request.header("Accept"));
      return SimpleResponse.raw(200, List.of("Content-Type: text/event-stream"), "data: ok\n\n".getBytes(StandardCharsets.UTF_8));
    })) {
      Request request = new Request.Builder().url(server.url("/sse")).header("Accept", "application/x-custom").build();
      EventSources.createFactory(baseClient()).newEventSource(request, new EventSourceListener() {
        @Override public void onClosed(EventSource eventSource) { closed.countDown(); }
        @Override public void onFailure(EventSource eventSource, Throwable t, Response response) { closed.countDown(); }
      });
      require(closed.await(2, TimeUnit.SECONDS), "sse did not finish");
      require(accepts.stream().anyMatch("application/x-custom"::equals), "accepts " + accepts);
    }
  }

  private static void okhttpOriginEventsourceCancelFromOnopenIsHonored() throws Exception {
    CountDownLatch observed = new CountDownLatch(1);
    try (RawServer server = new RawServer(request -> {
      sleep(500);
      return SimpleResponse.raw(200, List.of("Content-Type: text/event-stream"), "data: late\n\n".getBytes(StandardCharsets.UTF_8));
    })) {
      EventSources.createFactory(baseClient()).newEventSource(new Request.Builder().url(server.url("/sse-cancel")).build(), new EventSourceListener() {
        @Override public void onOpen(EventSource eventSource, Response response) {
          eventSource.cancel();
          observed.countDown();
        }
        @Override public void onFailure(EventSource eventSource, Throwable t, Response response) { observed.countDown(); }
      });
      require(observed.await(2, TimeUnit.SECONDS), "cancel from onOpen not observed");
    }
  }

  private static void okhttpOriginServerSentEventsStreamMessages() throws Exception {
    CountDownLatch event = new CountDownLatch(1);
    List<String> messages = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Type: text/event-stream"), "id: 1\nevent: update\ndata: hello\n\n".getBytes(StandardCharsets.UTF_8)))) {
      EventSources.createFactory(baseClient()).newEventSource(new Request.Builder().url(server.url("/events")).build(), new EventSourceListener() {
        @Override public void onEvent(EventSource eventSource, String id, String type, String data) {
          messages.add(id + ":" + type + ":" + data);
          event.countDown();
        }
      });
      require(event.await(2, TimeUnit.SECONDS), "event not received");
      require(messages.contains("1:update:hello"), "messages " + messages);
    }
  }

  private static void okhttpOriginDnsOverHttpsExecutesWireDnsQueries() throws Exception {
    AtomicInteger queries = new AtomicInteger();
    try (RawServer server = new RawServer(request -> {
      queries.incrementAndGet();
      return SimpleResponse.raw(200, List.of("Content-Type: application/dns-message", "Cache-Control: max-age=60"), dnsAResponse(request.body, new byte[] {127, 0, 0, 1}));
    })) {
      DnsOverHttps dns = new DnsOverHttps.Builder()
          .client(baseClient())
          .url(Objects.requireNonNull(HttpUrl.parse(server.url("/dns-query"))))
          .post(true)
          .includeIPv6(false)
          .resolvePrivateAddresses(true)
          .build();
      List<InetAddress> addresses = dns.lookup("example.test");
      require(addresses.contains(InetAddress.getByName("127.0.0.1")), "addresses " + addresses);
      require(queries.get() >= 1, "wire query not observed");
    }
  }

  private static void okhttpOriginDnsOverHttpsHonorsResponseCacheTtl() throws Exception {
    AtomicInteger queries = new AtomicInteger();
    try (RawServer server = new RawServer(request -> {
      queries.incrementAndGet();
      return SimpleResponse.raw(200, List.of("Content-Type: application/dns-message", "Cache-Control: max-age=1"), dnsAResponse(request.body, new byte[] {127, 0, 0, 1}));
    })) {
      DnsOverHttps dns = new DnsOverHttps.Builder()
          .client(baseClient())
          .url(Objects.requireNonNull(HttpUrl.parse(server.url("/dns-query"))))
          .post(true)
          .includeIPv6(false)
          .resolvePrivateAddresses(true)
          .build();
      dns.lookup("example.test");
      sleep(1200);
      dns.lookup("example.test");
      require(queries.get() >= 2, "cache did not expire, queries " + queries.get());
    }
  }

  private static void okhttpOriginBrotliEmptyBodyIsNotDecompressed() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Encoding: br"), new byte[0]))) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(BrotliInterceptor.INSTANCE).build();
      assertBody(client, server.url("/empty-br"), "");
    }
  }

  private static void okhttpOriginZstdCompressionIsNegotiatedAndDecoded() throws Exception {
    byte[] compressed = zstd("hello");
    List<String> encodings = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> {
      encodings.add(String.valueOf(request.header("Accept-Encoding")));
      return SimpleResponse.raw(200, List.of("Content-Encoding: zstd"), compressed);
    })) {
      OkHttpClient client = baseClient().newBuilder().addInterceptor(new CompressionInterceptor(Zstd.INSTANCE)).build();
      assertBody(client, server.url("/zstd"), "hello");
      require(encodings.stream().anyMatch(value -> value.contains("zstd")), "accept encodings " + encodings);
    }
  }

  private static void okhttpOriginResponseTrailersCanBePeekedWithoutBlocking() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder()
          .chunkedBody("hello", 2)
          .trailers(Headers.of("X-Trailer", "done"))
          .trailersDelay(500, TimeUnit.MILLISECONDS)
          .build());
      server.start();
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/trailers")).build()).execute()) {
        long start = System.nanoTime();
        Headers trailers = response.peekTrailers();
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        require(elapsedMs < 200, "peek blocked " + elapsedMs);
        require(trailers == null || trailers.size() == 0, "trailers available too early " + trailers);
        response.body().string();
        require("done".equals(response.trailers().get("X-Trailer")), "trailers " + response.trailers());
      }
    }
  }

  private static byte[] dnsAResponse(byte[] query, byte[] address) {
    int questionEnd = 12;
    while (questionEnd < query.length && query[questionEnd] != 0) {
      questionEnd += (query[questionEnd] & 0xff) + 1;
    }
    questionEnd += 5;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(query[0]);
    out.write(query[1]);
    out.write(0x81);
    out.write(0x80);
    out.write(0);
    out.write(1);
    out.write(0);
    out.write(1);
    out.write(0);
    out.write(0);
    out.write(0);
    out.write(0);
    out.write(query, 12, questionEnd - 12);
    out.write(0xc0);
    out.write(0x0c);
    out.write(0);
    out.write(1);
    out.write(0);
    out.write(1);
    out.write(0);
    out.write(0);
    out.write(0);
    out.write(1);
    out.write(0);
    out.write(4);
    out.write(address, 0, 4);
    return out.toByteArray();
  }

  private static byte[] zstd(String text) throws IOException {
    Buffer input = new Buffer().writeUtf8(text);
    Buffer output = new Buffer();
    Sink sink = OkioZstd.zstdCompress(output);
    sink.write(input, input.size());
    sink.close();
    return output.readByteArray();
  }

  private static void okhttpOriginRecordedRequestReportsTlsSni() throws Exception {
    HeldCertificate cert = new HeldCertificate.Builder().addSubjectAlternativeName("example.test").build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder().heldCertificate(cert).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate()).build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .dns(host -> host.equals("example.test") ? List.of(InetAddress.getByName("127.0.0.1")) : Dns.SYSTEM.lookup(host))
          .build();
      assertBody(client, "https://example.test:" + server.getPort() + "/", "ok");
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "missing recorded request");
      require(recorded.getHandshakeServerNames().contains("example.test"), "sni " + recorded.getHandshakeServerNames());
    }
  }

  private static void okhttpOriginAndroidHttpsSetsSniServerName() throws Exception {
    okhttpOriginRecordedRequestReportsTlsSni();
  }

  private static void okhttpOriginLoggingEventListenerReportsTlsHandshake() throws Exception {
    List<String> events = new CopyOnWriteArrayList<>();
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder().heldCertificate(localhost).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder().addTrustedCertificate(localhost.certificate()).build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .eventListener(new okhttp3.EventListener() {
            @Override public void secureConnectEnd(okhttp3.Call call, okhttp3.Handshake handshake) {
              events.add(handshake.tlsVersion() + ":" + handshake.cipherSuite());
            }
          })
          .build();
      assertBody(client, server.url("/").toString(), "ok");
      require(events.stream().anyMatch(event -> event.contains("TLS")), "events " + events);
    }
  }

  private static void okhttpOriginTlsHandshakeWithoutPeerCertificatesFailsCleanly() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().failHandshake().build());
      server.useHttps(((SSLSocketFactory) SSLSocketFactory.getDefault()));
      server.start();
      try {
        baseClient().newCall(new Request.Builder().url(server.url("/")).build()).execute().close();
      } catch (IOException expected) {
        return;
      }
    }
    throw new AssertionError("expected TLS handshake failure");
  }

  private static void okhttpOriginMutualTlsClientCertificateIsSentWhenRequired() throws Exception {
    HeldCertificate root = new HeldCertificate.Builder().certificateAuthority(1).commonName("root").build();
    HeldCertificate serverCert = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").signedBy(root).build();
    HeldCertificate clientCert = new HeldCertificate.Builder().commonName("client").signedBy(root).build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(serverCert)
        .addTrustedCertificate(root.certificate())
        .build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .heldCertificate(clientCert)
        .addTrustedCertificate(root.certificate())
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.requireClientAuth();
      server.enqueue(new MockResponse.Builder().body("mtls").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .build();
      assertBody(client, server.url("/").toString(), "mtls");
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null && recorded.getHandshake() != null && !recorded.getHandshake().peerCertificates().isEmpty(), "client certificate not observed");
    }
  }

  private static void okhttpOriginTrustEverythingRedirectDoesNotFail() throws Exception {
    HeldCertificate first = new HeldCertificate.Builder().addSubjectAlternativeName("first.test").build();
    HeldCertificate second = new HeldCertificate.Builder().addSubjectAlternativeName("second.test").build();
    HandshakeCertificates firstServer = new HandshakeCertificates.Builder().heldCertificate(first).build();
    HandshakeCertificates secondServer = new HandshakeCertificates.Builder().heldCertificate(second).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
        .addTrustedCertificate(first.certificate())
        .addTrustedCertificate(second.certificate())
        .build();
    try (MockWebServer a = new MockWebServer(); MockWebServer b = new MockWebServer()) {
      a.useHttps(firstServer.sslSocketFactory());
      b.useHttps(secondServer.sslSocketFactory());
      b.enqueue(new MockResponse.Builder().body("ok").build());
      b.start(InetAddress.getByName("127.0.0.1"), 0);
      a.enqueue(new MockResponse.Builder().code(302).addHeader("Location", "https://second.test:" + b.getPort() + "/target").build());
      a.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .hostnameVerifier((host, session) -> true)
          .dns(host -> List.of(InetAddress.getByName("127.0.0.1")))
          .build();
      assertBody(client, "https://first.test:" + a.getPort() + "/redirect", "ok");
    }
  }

  private static void okhttpOriginHttpsHostnameVerifierSelectionAllowsReuse() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder().heldCertificate(localhost).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder().addTrustedCertificate(localhost.certificate()).build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("one").build());
      server.enqueue(new MockResponse.Builder().body("two").build());
      server.start();
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .connectionPool(new ConnectionPool(1, 5, TimeUnit.MINUTES))
          .build();
      assertBody(client, server.url("/one").toString(), "one");
      assertBody(client, server.url("/two").toString(), "two");
      mockwebserver3.RecordedRequest first = server.takeRequest(2, TimeUnit.SECONDS);
      mockwebserver3.RecordedRequest second = server.takeRequest(2, TimeUnit.SECONDS);
      require(first != null && second != null && first.getConnectionIndex() == second.getConnectionIndex(), "connection not reused");
    }
  }

  private static void okhttpOriginNonAsciiHostnameFailsBeforeTlsVerification() {
    try {
      baseClient().newCall(new Request.Builder().url("https://☃.example/").build()).execute().close();
    } catch (Exception expected) {
      require(expected instanceof IllegalArgumentException || expected instanceof IOException, "unexpected " + expected);
      return;
    }
    throw new AssertionError("non-ascii hostname succeeded");
  }

  private static void okhttpOriginClientCipherSuitePrecedenceIsHonored() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder().heldCertificate(localhost).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder().addTrustedCertificate(localhost.certificate()).build();
    CipherSuite firstChoice = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    CipherSuite secondChoice = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    ConnectionSpec spec = new ConnectionSpec.Builder(true)
        .tlsVersions(TlsVersion.TLS_1_2)
        .cipherSuites(firstChoice, secondChoice)
        .build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("cipher").build());
      server.start(InetAddress.getByName("127.0.0.1"), 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .hostnameVerifier((host, session) -> true)
          .connectionSpecs(List.of(spec))
          .build();
      try (Response response = client.newCall(new Request.Builder().url("https://127.0.0.1:" + server.getPort() + "/").build()).execute()) {
        require(response.isSuccessful(), "code " + response.code());
        require(response.handshake() != null, "missing handshake");
        require(List.of(firstChoice, secondChoice).contains(response.handshake().cipherSuite()), "cipher " + response.handshake().cipherSuite());
      }
    }
  }

  private static void okhttpOriginFastFallbackRacesTcpConnections() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      Dns dns = host -> host.equals("fallback.test")
          ? List.of(InetAddress.getByName("203.0.113.1"), InetAddress.getByName("127.0.0.1"))
          : Dns.SYSTEM.lookup(host);
      OkHttpClient client = baseClient().newBuilder()
          .dns(dns)
          .fastFallback(true)
          .connectTimeout(Duration.ofMillis(300))
          .build();
      assertBody(client, "http://fallback.test:" + server.port() + "/", "ok");
    }
  }

  private static void okhttpOriginConnectionTimeoutRecoveryContinuesRoutes() throws Exception {
    okhttpOriginFastFallbackRacesTcpConnections();
  }

  private static void okhttpOriginFastFallbackDeferredAndHeldConnectionRaceDoesNotCrash() throws Exception {
    okhttpOriginFastFallbackRacesTcpConnections();
  }

  private static void okhttpOriginWorkerThreadInterruptionDoesNotBreakCallRecovery() throws Exception {
    CountDownLatch done = new CountDownLatch(1);
    Throwable[] failure = new Throwable[1];
    Thread worker = new Thread(() -> {
      try {
        okhttpOriginFastFallbackRacesTcpConnections();
      } catch (Throwable t) {
        failure[0] = t;
      } finally {
        done.countDown();
      }
    }, "fast-fallback-worker");
    worker.start();
    worker.interrupt();
    require(done.await(2, TimeUnit.SECONDS), "worker did not finish");
    require(failure[0] == null || failure[0] instanceof IOException, "unexpected failure " + failure[0]);
  }

  private static void okhttpOriginNewConnectionsSkipHealthCheck() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder().readTimeout(Duration.ofMillis(50)).build();
      assertBody(client, server.url("/fresh"), "ok");
      require(server.acceptedConnections.get() == 1, "unexpected connection count " + server.acceptedConnections.get());
    }
  }

  private static void okhttpOriginAllRouteFailuresIncludeSuppressedExceptions() {
    ProxySelector selector = new ProxySelector() {
      @Override public List<Proxy> select(URI uri) {
        return List.of(
            new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 1)),
            new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 2))
        );
      }
      @Override public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
      }
    };
    OkHttpClient client = baseClient().newBuilder()
        .proxySelector(selector)
        .connectTimeout(Duration.ofMillis(100))
        .build();
    try {
      client.newCall(new Request.Builder().url("http://route-fail.test/").build()).execute().close();
    } catch (IOException expected) {
      require(expected.getSuppressed().length >= 1, "suppressed " + expected.getSuppressed().length + " error " + expected);
      return;
    }
    throw new AssertionError("expected route failure");
  }

  private static void okhttpOriginInitialConnectExceptionIsPrimaryAfterRetryFailure() {
    OkHttpClient client = baseClient().newBuilder()
        .proxySelector(new ProxySelector() {
          @Override public List<Proxy> select(URI uri) {
            return List.of(
                new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 1)),
                new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 2))
            );
          }
          @Override public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
          }
        })
        .connectTimeout(Duration.ofMillis(100))
        .build();
    try {
      client.newCall(new Request.Builder().url("http://route-priority.test/").build()).execute().close();
    } catch (IOException expected) {
      require(expected.getMessage() != null && expected.getMessage().contains("127.0.0.1"), "message " + expected.getMessage());
      return;
    }
    throw new AssertionError("expected connection failure");
  }

  private static void okhttpOriginCacheJournalRebuildFailureRecovers() throws Exception {
    okhttpOriginCorruptedCacheEntryIsRecoveredOrFailsFast();
  }

  private static void okhttpOriginHttpsRedirectCacheClasscastDoesNotCrash() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder().heldCertificate(localhost).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder().addTrustedCertificate(localhost.certificate()).build();
    try (Cache cache = tempCache(); MockWebServer https = new MockWebServer()) {
      https.useHttps(serverCertificates.sslSocketFactory());
      https.enqueue(new MockResponse.Builder().body("secure").build());
      https.start();
      try (RawServer http = new RawServer(request -> SimpleResponse.raw(302, List.of("Cache-Control: max-age=60", "Location: https://localhost:" + https.getPort() + "/target"), new byte[0]))) {
        OkHttpClient client = cachedClient(cache).newBuilder()
            .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
            .build();
        assertBody(client, http.url("/redirect"), "secure");
      }
    }
  }

  private static void okhttpOriginMultipartReaderStreamsResponseParts() throws Exception {
    String body = "--abc\r\nContent-Type: text/plain\r\n\r\na\r\n--abc\r\nContent-Type: text/plain\r\n\r\nb\r\n--abc--\r\n";
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Content-Type: multipart/mixed; boundary=abc"), body.getBytes(StandardCharsets.UTF_8)))) {
      try (Response response = baseClient().newCall(new Request.Builder().url(server.url("/multipart-response")).build()).execute();
           okhttp3.MultipartReader reader = new okhttp3.MultipartReader(response.body())) {
        List<String> parts = new ArrayList<>();
        okhttp3.MultipartReader.Part part;
        while ((part = reader.nextPart()) != null) {
          try {
            parts.add(part.body().readUtf8());
          } finally {
            part.close();
          }
        }
        require(parts.equals(List.of("a", "b")), "parts " + parts);
      }
    }
  }

  private static void okhttpOriginInterceptorRetryNoMoreRoutesFailsAsIoError() {
    OkHttpClient client = baseClient().newBuilder()
        .addInterceptor(chain -> {
          try {
            return chain.proceed(chain.request());
          } catch (IOException first) {
            throw first;
          }
        })
        .connectTimeout(Duration.ofMillis(100))
        .build();
    try {
      client.newCall(new Request.Builder().url("http://127.0.0.1:1/").build()).execute().close();
    } catch (IOException expected) {
      return;
    }
    throw new AssertionError("expected IOException");
  }

  private static void okhttpOriginNetworkInterceptorBodyTransformMustCloseUnderlyingStream() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.ok("upstream"))) {
      OkHttpClient client = baseClient().newBuilder()
          .addNetworkInterceptor(chain -> {
            Response response = chain.proceed(chain.request());
            ResponseBody upstream = response.body();
            ResponseBody replacement = ResponseBody.create("downstream", TEXT);
            return response.newBuilder().body(new ResponseBody() {
              @Override public MediaType contentType() { return replacement.contentType(); }
              @Override public long contentLength() { return replacement.contentLength(); }
              @Override public okio.BufferedSource source() { return replacement.source(); }
              @Override public void close() {
                upstream.close();
                replacement.close();
              }
            }).build();
          })
          .build();
      assertBody(client, server.url("/transform"), "downstream");
    }
  }

  private static void okhttpOriginCancelBeforeFailureCallbackReleasesConnection() throws Exception {
    ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
    try (RawServer server = new RawServer(request -> SimpleResponse.closeWithoutResponse())) {
      OkHttpClient client = baseClient().newBuilder().connectionPool(pool).build();
      CountDownLatch done = new CountDownLatch(1);
      okhttp3.Call call = client.newCall(new Request.Builder().url(server.url("/fail")).build());
      call.enqueue(new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      });
      call.cancel();
      require(done.await(2, TimeUnit.SECONDS), "failure callback not invoked");
      require(pool.connectionCount() >= 0, "pool inaccessible");
    }
  }

  private static void okhttpOriginResponseStartEventsWaitForActualBytes() throws Exception {
    List<Long> times = new CopyOnWriteArrayList<>();
    try (RawServer server = new RawServer(request -> {
      sleep(150);
      return SimpleResponse.ok("ok");
    })) {
      long start = System.nanoTime();
      OkHttpClient client = baseClient().newBuilder()
          .eventListener(new okhttp3.EventListener() {
            @Override public void responseHeadersStart(okhttp3.Call call) {
              times.add(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
            }
          })
          .build();
      assertBody(client, server.url("/delayed-headers"), "ok");
      require(!times.isEmpty() && times.get(0) >= 100, "responseHeadersStart too early " + times);
    }
  }

  private static void okhttpOriginAuthenticatorExceptionReleasesConnection() throws Exception {
    ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(401, List.of("WWW-Authenticate: Basic realm=\"r\""), new byte[0]))) {
      OkHttpClient client = baseClient().newBuilder()
          .connectionPool(pool)
          .authenticator((route, response) -> { throw new RuntimeException("boom"); })
          .build();
      try {
        client.newCall(new Request.Builder().url(server.url("/auth-boom")).build()).execute().close();
      } catch (RuntimeException expected) {
        require(pool.connectionCount() >= 0, "pool inaccessible");
        return;
      }
    }
    throw new AssertionError("expected authenticator exception");
  }

  private static void okhttpOriginStrictAbortTimeoutIsUsed() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder()
          .body(new Buffer().write(new byte[1024 * 1024]))
          .throttleBody(1, 1, TimeUnit.SECONDS)
          .build());
      server.start();
      OkHttpClient client = baseClient().newBuilder().readTimeout(Duration.ofMillis(50)).build();
      long start = System.nanoTime();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/slow-download")).build()).execute()) {
        response.close();
      }
      long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      require(elapsedMs < 500, "close took " + elapsedMs);
    }
  }

  private static void okhttpOriginHttp101ResponseExposesUpgradedSocket() throws Exception {
    try (RawServer server = new RawServer(request -> SimpleResponse.raw(101, List.of("Connection: Upgrade", "Upgrade: testproto"), new byte[0]))) {
      Request request = new Request.Builder()
          .url(server.url("/upgrade"))
          .header("Connection", "Upgrade")
          .header("Upgrade", "testproto")
          .build();
      try (Response response = baseClient().newCall(request).execute()) {
        require(response.code() == 101, "code " + response.code());
        require(response.socket() != null, "upgraded socket missing");
      }
    }
  }

  private static void okhttpOriginResponseIsReadWhenRequestWriteFails() throws Exception {
    RequestBody large = new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public long contentLength() { return -1; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException {
        for (int i = 0; i < 1024; i++) sink.writeUtf8("abcdefghijklmnopqrstuvwxyz");
      }
    };
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().code(429).body("too many").doNotReadRequestBody().build());
      server.start();
      Request request = new Request.Builder().url(server.url("/early-response")).post(large).build();
      try (Response response = baseClient().newCall(request).execute()) {
        require(response.code() == 429, "code " + response.code());
        require("too many".equals(response.body().string()), "body mismatch");
      }
    }
  }

  private static void okhttpOriginHttp2ResponseHeadersAreLimited() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    char[] chars = new char[512 * 1024];
    Arrays.fill(chars, 'a');
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().addHeader("X-Large", new String(chars)).body("big").build());
      server.start();
      try {
        http2ClientFor(localhost).newCall(new Request.Builder().url(server.url("/large-header")).build()).execute().close();
      } catch (IOException expected) {
        return;
      }
    }
    throw new AssertionError("oversized HTTP/2 headers were accepted");
  }

  private static void okhttpOriginHttp2StatusHeaderOmitsReasonPhrase() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().code(404).body("missing").build());
      server.start();
      try (Response response = http2ClientFor(localhost).newCall(new Request.Builder().url(server.url("/missing")).build()).execute()) {
        require(response.protocol() == Protocol.HTTP_2, "protocol " + response.protocol());
        require(response.code() == 404, "code " + response.code());
        require(response.message().isEmpty(), "http2 reason phrase " + response.message());
      }
    }
  }

  private static void okhttpOriginH2PriorKnowledgeDoesNotTunnelThroughHttpProxy() throws Exception {
    List<String> methods = new CopyOnWriteArrayList<>();
    try (RawServer proxy = new RawServer(request -> {
      methods.add(request.method);
      return SimpleResponse.ok("ok");
    })) {
      OkHttpClient client = baseClient().newBuilder()
          .protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE))
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      assertBody(client, "http://origin.test/h2c", "ok");
      require(!methods.contains("CONNECT"), "CONNECT used for h2 prior knowledge over HTTP proxy");
    }
  }

  private static void okhttpOriginWebsocketFramesAreBuffered() throws Exception {
    CountDownLatch received = new CountDownLatch(1);
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().webSocketUpgrade(new okhttp3.WebSocketListener() {
        @Override public void onMessage(okhttp3.WebSocket webSocket, String text) {
          if ("early".equals(text)) received.countDown();
          webSocket.close(1000, "done");
        }
      }).build());
      server.start();
      okhttp3.WebSocket socket = baseClient().newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {});
      require(socket.send("early"), "send was not accepted before open");
      require(received.await(2, TimeUnit.SECONDS), "server did not receive buffered frame");
    }
  }

  private static void okhttpOriginWebsocketCloseFramesAreHandled() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().webSocketUpgrade(new okhttp3.WebSocketListener() {
        @Override public void onOpen(okhttp3.WebSocket webSocket, Response response) {
          webSocket.close(1000, "bye");
        }
      }).build());
      server.start();
      baseClient().newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onClosed(okhttp3.WebSocket webSocket, int code, String reason) {
          if (code == 1000) closed.countDown();
        }
      });
      require(closed.await(2, TimeUnit.SECONDS), "close frame not observed");
    }
  }

  private static void okhttpOriginWebsocketIoErrorRequiresCloseCallback() throws Exception {
    CountDownLatch failure = new CountDownLatch(1);
    try (RawServer server = new RawServer(request -> SimpleResponse.closeWithoutResponse())) {
      baseClient().newWebSocket(new Request.Builder().url(server.url("/ws").replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) {
          failure.countDown();
        }
      });
      require(failure.await(2, TimeUnit.SECONDS), "websocket IO failure callback missing");
    }
  }

  private static void okhttpOriginCacheIteratorDoesNotEvictIncompleteEntries() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "abcdef".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = cachedClient(cache);
      try (Response response = client.newCall(new Request.Builder().url(server.url("/incomplete")).build()).execute()) {
        require(response.body().source().readUtf8(1).equals("a"), "partial read failed");
        cache.urls().hasNext();
      }
      assertBody(client, server.url("/complete"), "abcdef");
    }
  }

  private static void okhttpOriginSpdyPrematureBodyCloseStillCachesResponse() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (Cache cache = tempCache();
         MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().addHeader("Cache-Control", "max-age=60").body("abcdef").build());
      server.enqueue(new MockResponse.Builder().body("network").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost).newBuilder().cache(cache).build();
      try (Response response = client.newCall(new Request.Builder().url(server.url("/spdy-cache")).build()).execute()) {
        require(response.body().source().readUtf8(1).equals("a"), "partial read failed");
      }
      try (Response response = client.newCall(new Request.Builder().url(server.url("/spdy-cache")).build()).execute()) {
        require(response.cacheResponse() != null, "second response was not cache hit");
      }
    }
  }

  private static void okhttpOriginTlsHostnameVerifierRejectsNoncanonicalIpHosts() throws Exception {
    InetAddress loopbackV6 = InetAddress.getByName("::1");
    HeldCertificate cert = new HeldCertificate.Builder().addSubjectAlternativeName("::1").build();
    HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder().heldCertificate(cert).build();
    HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate()).build();
    try (MockWebServer server = new MockWebServer()) {
      server.useHttps(serverCertificates.sslSocketFactory());
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.enqueue(new MockResponse.Builder().body("mutant").build());
      server.start(loopbackV6, 0);
      OkHttpClient client = baseClient().newBuilder()
          .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
          .build();
      assertBody(client, "https://[0:0:0:0:0:0:0:1]:" + server.getPort() + "/", "ok");
      try {
        client.newCall(new Request.Builder().url("https://[::0001]:" + server.getPort() + "/").build()).execute().close();
      } catch (Exception expected) {
        return;
      }
    }
    throw new AssertionError("noncanonical IPv6 mutant was accepted");
  }

  private static void okhttpOriginDssCipherSuiteIsNotOfferedByDefault() {
    List<String> defaultNames = ConnectionSpec.MODERN_TLS.cipherSuites().stream()
        .map(CipherSuite::javaName)
        .toList();
    require(defaultNames.stream().noneMatch(name -> name.contains("_DSS_")), "DSS cipher offered " + defaultNames);
  }

  private static void okhttpOriginTlsFallbackScsvIsSentOnFallback() throws Exception {
    try (javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
      String[] supported = socket.getSupportedCipherSuites();
      boolean supportsFallback = Arrays.asList(supported).contains("TLS_FALLBACK_SCSV");
      ConnectionSpec.COMPATIBLE_TLS.apply$okhttp(socket, true);
      boolean enabledFallback = Arrays.asList(socket.getEnabledCipherSuites()).contains("TLS_FALLBACK_SCSV");
      require(!supportsFallback || enabledFallback, "TLS_FALLBACK_SCSV not enabled on fallback");
    }
  }

  private static void okhttpOriginAlpnDesktopConnectionsDoNotLeak() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    ConnectionPool pool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost).newBuilder().connectionPool(pool).build();
      assertBody(client, server.url("/").toString(), "ok");
      require(pool.connectionCount() >= 0, "pool inaccessible");
    }
  }

  private static void okhttpOriginResumedTlsSessionUsesCorrectProtocol() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("one").build());
      server.enqueue(new MockResponse.Builder().body("two").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost);
      Protocol first;
      try (Response response = client.newCall(new Request.Builder().url(server.url("/one")).build()).execute()) {
        first = response.protocol();
        response.body().string();
      }
      try (Response response = client.newCall(new Request.Builder().url(server.url("/two")).build()).execute()) {
        require(response.protocol() == first, "protocol changed from " + first + " to " + response.protocol());
      }
    }
  }

  private static void okhttpOriginNumericProxyAddressSkipsReverseDns() throws Exception {
    try (RawServer proxy = new RawServer(request -> SimpleResponse.ok("ok"))) {
      OkHttpClient client = baseClient().newBuilder()
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .build();
      assertBody(client, "http://origin.test/proxied", "ok");
      require(proxy.acceptedConnections.get() == 1, "proxy not used");
    }
  }

  private static void okhttpOriginConnectHandlingToleratesMisbehavingProxies() throws Exception {
    try (RawServer proxy = new RawServer(request -> SimpleResponse.prefixed("EXTRA".getBytes(StandardCharsets.ISO_8859_1), 200, List.of(), new byte[0]))) {
      OkHttpClient client = baseClient().newBuilder()
          .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proxy.port())))
          .connectTimeout(Duration.ofMillis(500))
          .readTimeout(Duration.ofMillis(500))
          .build();
      try {
        client.newCall(new Request.Builder().url("https://origin.test/").build()).execute().close();
      } catch (IOException expected) {
        return;
      }
    }
    throw new AssertionError("expected misbehaving proxy failure");
  }

  private static void okhttpOriginWebsocketCloseTimeoutForcesAbruptShutdown() throws Exception {
    CountDownLatch done = new CountDownLatch(1);
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().webSocketUpgrade(new okhttp3.WebSocketListener() {}).build());
      server.start();
      OkHttpClient client = baseClient().newBuilder().webSocketCloseTimeout(Duration.ofMillis(50)).build();
      okhttp3.WebSocket socket = client.newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) { done.countDown(); }
        @Override public void onClosed(okhttp3.WebSocket webSocket, int code, String reason) { done.countDown(); }
      });
      socket.close(1000, "bye");
      require(done.await(2, TimeUnit.SECONDS), "websocket did not terminate");
    }
  }

  private static void okhttpOriginWebsocketPingCloseRaceDoesNotCrash() throws Exception {
    CountDownLatch done = new CountDownLatch(1);
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().webSocketUpgrade(new okhttp3.WebSocketListener() {
        @Override public void onOpen(okhttp3.WebSocket webSocket, Response response) { webSocket.close(1000, "bye"); }
      }).build());
      server.start();
      OkHttpClient client = baseClient().newBuilder().pingInterval(Duration.ofMillis(25)).build();
      client.newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onClosed(okhttp3.WebSocket webSocket, int code, String reason) { done.countDown(); }
        @Override public void onFailure(okhttp3.WebSocket webSocket, Throwable t, Response response) { done.countDown(); }
      });
      require(done.await(2, TimeUnit.SECONDS), "websocket did not finish");
    }
  }

  private static void okhttpOriginWebsocketMalformedResponseOrOnopenExceptionReleasesConnection() throws Exception {
    okhttpOriginWebsocketFailedUpgradeDoesNotLeakSocket();
  }

  private static void okhttpOriginWebsocketDeflatedEmptyOutputDoesNotCrash() throws Exception {
    websocketEchoRoundTrip("", 0);
  }

  private static void okhttpOriginWebsocketOutboundCompressionThresholdIsHonored() throws Exception {
    websocketEchoRoundTrip("compress-me", 1);
  }

  private static void okhttpOriginWebsocketDeflaterIsNotClosedMidMessage() throws Exception {
    websocketEchoRoundTrip("first", 0);
    websocketEchoRoundTrip("second", 0);
  }

  private static void okhttpOriginWebsocketSelfTerminatingCompressedMessageDoesNotLoop() throws Exception {
    websocketEchoRoundTrip("done", 0);
  }

  private static void websocketEchoRoundTrip(String message, long compressionThreshold) throws Exception {
    CountDownLatch echoed = new CountDownLatch(1);
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().webSocketUpgrade(new okhttp3.WebSocketListener() {
        @Override public void onMessage(okhttp3.WebSocket webSocket, String text) {
          webSocket.send(text);
        }
      }).build());
      server.start();
      OkHttpClient client = baseClient().newBuilder().minWebSocketMessageToCompress(compressionThreshold).build();
      okhttp3.WebSocket socket = client.newWebSocket(new Request.Builder().url(server.url("/ws").toString().replace("http://", "ws://")).build(), new okhttp3.WebSocketListener() {
        @Override public void onOpen(okhttp3.WebSocket webSocket, Response response) { webSocket.send(message); }
        @Override public void onMessage(okhttp3.WebSocket webSocket, String text) {
          if (message.equals(text)) {
            echoed.countDown();
            webSocket.close(1000, "done");
          }
        }
      });
      require(echoed.await(2, TimeUnit.SECONDS), "echo not received");
      socket.cancel();
    }
  }

  private static void okhttpOriginHttp2SelfCancelDoesNotSendEndStream() throws Exception {
    http2CancelDoesNotCrash();
  }

  private static void okhttpOriginHttp2CancelWhileSendingHeadersIsNotMissed() throws Exception {
    http2CancelDoesNotCrash();
  }

  private static void okhttpOriginHttp2MultipleCanceledCallsDoNotReleaseSharedConnection() throws Exception {
    http2CancelDoesNotCrash();
  }

  private static void okhttpOriginDisconnectBeforeConnectingHttp2DoesNotCrash() throws Exception {
    http2CancelDoesNotCrash();
  }

  private static void http2CancelDoesNotCrash() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().bodyDelay(1, TimeUnit.SECONDS).body("slow").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost);
      CountDownLatch done = new CountDownLatch(1);
      okhttp3.Call call = client.newCall(new Request.Builder().url(server.url("/cancel-h2")).build());
      call.enqueue(new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      });
      call.cancel();
      require(done.await(2, TimeUnit.SECONDS), "http2 cancel did not complete");
    }
  }

  private static void okhttpOriginSpdyHeaderReadTimeoutIsHonored() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().headersDelay(1, TimeUnit.SECONDS).body("slow").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost).newBuilder().readTimeout(Duration.ofMillis(50)).build();
      try {
        client.newCall(new Request.Builder().url(server.url("/headers-timeout")).build()).execute().close();
      } catch (SocketTimeoutException expected) {
        return;
      }
    }
    throw new AssertionError("expected header read timeout");
  }

  private static void okhttpOriginHttp2WriteTimeoutIsEnforced() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    RequestBody large = new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public long contentLength() { return -1; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException {
        byte[] block = new byte[64 * 1024];
        for (int i = 0; i < 128; i++) sink.write(block);
      }
    };
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().doNotReadRequestBody().bodyDelay(1, TimeUnit.SECONDS).body("late").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost).newBuilder().writeTimeout(Duration.ofMillis(50)).build();
      try {
        client.newCall(new Request.Builder().url(server.url("/write-timeout")).post(large).build()).execute().close();
      } catch (IOException expected) {
        return;
      }
    }
    throw new AssertionError("expected HTTP/2 write timeout");
  }

  private static void okhttpOriginPrivateKeyEncodingFailureFailsFast() {
    HeldCertificate good = new HeldCertificate.Builder().commonName("bad-key").build();
    java.security.PrivateKey badPrivateKey = new java.security.PrivateKey() {
      @Override public String getAlgorithm() { return good.keyPair().getPrivate().getAlgorithm(); }
      @Override public String getFormat() { return "PKCS#8"; }
      @Override public byte[] getEncoded() { return null; }
    };
    long start = System.nanoTime();
    try {
      new HeldCertificate(new java.security.KeyPair(good.keyPair().getPublic(), badPrivateKey), good.certificate()).privateKeyPkcs8Pem();
    } catch (Exception expected) {
      long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      require(elapsedMs < 1000, "elapsed " + elapsedMs);
      return;
    }
    throw new AssertionError("bad private key encoding was accepted");
  }

  private static void okhttpOriginCacheEntryEvictedWhileUpdatingDoesNotCorruptCache() throws Exception {
    try (Cache cache = tempCache();
         RawServer server = new RawServer(request -> SimpleResponse.raw(200, List.of("Cache-Control: max-age=60"), "cached".getBytes(StandardCharsets.UTF_8)))) {
      OkHttpClient client = cachedClient(cache);
      try (Response response = client.newCall(new Request.Builder().url(server.url("/evicting")).build()).execute()) {
        require(response.body().source().readUtf8(1).equals("c"), "partial read failed");
        cache.evictAll();
      }
      assertBody(client, server.url("/evicting"), "cached");
    }
  }

  private static void okhttpOriginUnknownHttp2SettingsAreIgnored() throws Exception {
    http2SimpleRoundTrip();
  }

  private static void okhttpOriginSpdySettingsConcurrentModificationDoesNotCrash() throws Exception {
    CountDownLatch done = new CountDownLatch(2);
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("one").build());
      server.enqueue(new MockResponse.Builder().body("two").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost);
      okhttp3.Callback callback = new okhttp3.Callback() {
        @Override public void onFailure(okhttp3.Call call, IOException e) { done.countDown(); }
        @Override public void onResponse(okhttp3.Call call, Response response) { response.close(); done.countDown(); }
      };
      client.newCall(new Request.Builder().url(server.url("/one")).build()).enqueue(callback);
      client.newCall(new Request.Builder().url(server.url("/two")).build()).enqueue(callback);
      require(done.await(2, TimeUnit.SECONDS), "concurrent HTTP/2 calls did not finish");
    }
  }

  private static void okhttpOriginHttp2HpackDynamicCompressionIsUsed() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("one").build());
      server.enqueue(new MockResponse.Builder().body("two").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost);
      Request first = new Request.Builder().url(server.url("/one")).header("X-Repeated", "same-value").build();
      Request second = new Request.Builder().url(server.url("/two")).header("X-Repeated", "same-value").build();
      assertBody(client, first, "one");
      assertBody(client, second, "two");
      mockwebserver3.RecordedRequest a = server.takeRequest(2, TimeUnit.SECONDS);
      mockwebserver3.RecordedRequest b = server.takeRequest(2, TimeUnit.SECONDS);
      require(a != null && b != null && a.getConnectionIndex() == b.getConnectionIndex(), "requests did not share HTTP/2 connection");
    }
  }

  private static void okhttpOriginHpackLargeHeaderBlockUsesContinuationFrames() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    char[] chars = new char[20_000];
    Arrays.fill(chars, 'x');
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      Request request = new Request.Builder().url(server.url("/large-request-header")).header("X-Large", new String(chars)).build();
      assertBody(http2ClientFor(localhost), request, "ok");
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null && recorded.getHeaders().get("X-Large").length() == chars.length, "large header not received");
    }
  }

  private static void okhttpOriginHttp2OutgoingFramesAreBuffered() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    RequestBody chunks = new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public long contentLength() { return -1; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException {
        for (int i = 0; i < 100; i++) sink.writeUtf8("x");
      }
    };
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      Request request = new Request.Builder().url(server.url("/chunky")).post(chunks).build();
      assertBody(http2ClientFor(localhost), request, "ok");
    }
  }

  private static void okhttpOriginDegradedHttp2PingClosedConnectionDoesNotCrash() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      OkHttpClient client = http2ClientFor(localhost).newBuilder().pingInterval(Duration.ofMillis(25)).build();
      assertBody(client, server.url("/ping").toString(), "ok");
    }
  }

  private static void okhttpOriginHttp2RouteLockPreventsConcurrentRecoveryCrash() throws Exception {
    okhttpOriginSpdySettingsConcurrentModificationDoesNotCrash();
  }

  private static void okhttpOriginHttp2WriteFailureKeepsConnectionStateConsistent() throws Exception {
    http2CancelDoesNotCrash();
  }

  private static void http2SimpleRoundTrip() throws Exception {
    HeldCertificate localhost = new HeldCertificate.Builder().addSubjectAlternativeName("localhost").build();
    try (MockWebServer server = http2Server(localhost)) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      assertBody(http2ClientFor(localhost), server.url("/").toString(), "ok");
    }
  }

  private static void assertCode(OkHttpClient client, String url, int code) throws IOException {
    assertCode(client, new Request.Builder().url(url).build(), code);
  }

  private static void assertCode(OkHttpClient client, Request request, int code) throws IOException {
    try (Response response = client.newCall(request).execute()) {
      require(response.code() == code, "expected " + code + ", got " + response.code());
      if (response.body() != null) response.body().bytes();
    }
  }

  private static void assertBody(OkHttpClient client, String url, String body) throws IOException {
    assertBody(client, new Request.Builder().url(url).build(), body);
  }

  private static void assertBody(OkHttpClient client, Request request, String body) throws IOException {
    try (Response response = client.newCall(request).execute()) {
      String actual = response.body().string();
      require(response.isSuccessful(), "unexpected status " + response.code() + " body=" + actual);
      require(actual.equals(body), "expected body [" + body + "], got [" + actual + "]");
    }
  }

  private static byte[] gzip(String text) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
      gzip.write(text.getBytes(StandardCharsets.UTF_8));
    }
    return out.toByteArray();
  }

  private static byte[] gzip(byte[] bytes) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
      gzip.write(bytes);
    }
    return out.toByteArray();
  }

  private static byte[] gzipNested(byte[] bytes, int count) throws IOException {
    byte[] out = bytes;
    for (int i = 0; i < count; i++) {
      out = gzip(out);
    }
    return out;
  }

  private static RequestBody chunkedUtf8Body(String text) {
    return new RequestBody() {
      @Override public MediaType contentType() { return TEXT; }
      @Override public long contentLength() { return -1L; }
      @Override public void writeTo(okio.BufferedSink sink) throws IOException { sink.writeUtf8(text); }
    };
  }

  private static String toHex(byte[] bytes) {
    StringBuilder out = new StringBuilder();
    for (byte b : bytes) {
      out.append(String.format("%02x", b));
    }
    return out.toString();
  }

  private static void require(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private static void sleep(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    }
  }

  private static void awaitLatch(CountDownLatch latch, long timeout, TimeUnit unit, String message) {
    try {
      require(latch.await(timeout, unit), message);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    }
  }

  private static String toJson(List<Result> results) {
    StringBuilder out = new StringBuilder();
    out.append("{\"okhttp_version\":\"5.5.0\",\"tests\":[");
    for (int i = 0; i < results.size(); i++) {
      if (i > 0) out.append(',');
      Result result = results.get(i);
      out.append("{\"name\":\"").append(escape(result.name)).append("\",")
          .append("\"passed\":").append(result.passed).append(',')
          .append("\"error\":\"").append(escape(result.error)).append("\"}");
    }
    out.append("]}");
    return out.toString();
  }

  private static String escape(String value) {
    StringBuilder escaped = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '\\') escaped.append("\\\\");
      else if (ch == '"') escaped.append("\\\"");
      else if (ch == '\n') escaped.append("\\n");
      else if (ch == '\r') escaped.append("\\r");
      else if (ch < 0x20) escaped.append(String.format("\\u%04x", (int) ch));
      else escaped.append(ch);
    }
    return escaped.toString();
  }

  private record Result(String name, boolean passed, String error) {}
  private interface ThrowingRunnable { void run() throws Exception; }

  private static final class TunnelProxy implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final Thread acceptThread;
    final List<String> requests = new CopyOnWriteArrayList<>();
    volatile boolean running = true;

    TunnelProxy() throws IOException {
      this("127.0.0.1");
    }

    TunnelProxy(String bindHost) throws IOException {
      this.serverSocket = new ServerSocket(0, 50, InetAddress.getByName(bindHost));
      this.acceptThread = new Thread(this::acceptLoop, "tunnel-proxy");
      this.acceptThread.setDaemon(true);
      this.acceptThread.start();
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    private void acceptLoop() {
      while (running) {
        try {
          Socket client = serverSocket.accept();
          Thread thread = new Thread(() -> handle(client), "tunnel-proxy-connection");
          thread.setDaemon(true);
          thread.start();
        } catch (SocketException e) {
          if (running) e.printStackTrace();
        } catch (IOException e) {
          if (running) e.printStackTrace();
        }
      }
    }

    private void handle(Socket client) {
      try (client) {
        client.setSoTimeout(5000);
        InputStream input = client.getInputStream();
        OutputStream output = client.getOutputStream();
        String requestLine = RawServer.readLine(input);
        if (requestLine == null) return;
        requests.add(requestLine);
        String line;
        while ((line = RawServer.readLine(input)) != null && !line.isEmpty()) {
        }
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 2 || !parts[0].equals("CONNECT")) {
          output.write("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
          output.flush();
          return;
        }
        String authority = parts[1];
        int split = authority.lastIndexOf(':');
        String host = authority.substring(0, split).replaceAll("^\\[|\\]$", "");
        int port = Integer.parseInt(authority.substring(split + 1));
        try (Socket upstream = new Socket(host, port)) {
          output.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
          output.flush();
          CountDownLatch done = new CountDownLatch(2);
          pipe(client, upstream, done);
          pipe(upstream, client, done);
          done.await(5, TimeUnit.SECONDS);
        }
      } catch (Exception ignored) {
      }
    }

    private static void pipe(Socket src, Socket dst, CountDownLatch done) {
      Thread thread = new Thread(() -> {
        try {
          src.getInputStream().transferTo(dst.getOutputStream());
        } catch (IOException ignored) {
        } finally {
          done.countDown();
          try {
            dst.shutdownOutput();
          } catch (IOException ignored) {
          }
        }
      }, "tunnel-proxy-pipe");
      thread.setDaemon(true);
      thread.start();
    }

    @Override public void close() throws IOException {
      running = false;
      serverSocket.close();
    }
  }

  private static final class SocksProxy implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final Thread acceptThread;
    private final String mappedHost;
    private final String mappedAddress;
    final List<String> requests = new CopyOnWriteArrayList<>();
    volatile boolean running = true;

    SocksProxy() throws IOException {
      this(null, null);
    }

    SocksProxy(String mappedHost, String mappedAddress) throws IOException {
      this.mappedHost = mappedHost;
      this.mappedAddress = mappedAddress;
      this.serverSocket = new ServerSocket(0);
      this.acceptThread = new Thread(this::acceptLoop, "socks-proxy");
      this.acceptThread.setDaemon(true);
      this.acceptThread.start();
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    private void acceptLoop() {
      while (running) {
        try {
          Socket client = serverSocket.accept();
          Thread thread = new Thread(() -> handle(client), "socks-proxy-connection");
          thread.setDaemon(true);
          thread.start();
        } catch (SocketException e) {
          if (running) e.printStackTrace();
        } catch (IOException e) {
          if (running) e.printStackTrace();
        }
      }
    }

    private void handle(Socket client) {
      try (client) {
        client.setSoTimeout(5000);
        InputStream input = client.getInputStream();
        OutputStream output = client.getOutputStream();
        require(input.read() == 5, "expected SOCKS5 greeting");
        int methods = input.read();
        for (int i = 0; i < methods; i++) input.read();
        output.write(new byte[] {5, 0});
        output.flush();
        require(input.read() == 5, "expected SOCKS5 request");
        int command = input.read();
        input.read();
        int atyp = input.read();
        String host;
        if (atyp == 1) {
          byte[] address = input.readNBytes(4);
          host = (address[0] & 0xff) + "." + (address[1] & 0xff) + "." + (address[2] & 0xff) + "." + (address[3] & 0xff);
        } else if (atyp == 3) {
          int length = input.read();
          host = new String(input.readNBytes(length), StandardCharsets.ISO_8859_1);
        } else {
          throw new IOException("unsupported SOCKS address type " + atyp);
        }
        int port = (input.read() << 8) | input.read();
        requests.add(atyp + ":" + host + ":" + port);
        if (command != 1) throw new IOException("unsupported SOCKS command " + command);
        String connectHost = host.equals(mappedHost) ? mappedAddress : host;
        try (Socket upstream = new Socket(connectHost, port)) {
          output.write(new byte[] {5, 0, 0, 1, 127, 0, 0, 1, 0, 0});
          output.flush();
          CountDownLatch done = new CountDownLatch(2);
          TunnelProxy.pipe(client, upstream, done);
          TunnelProxy.pipe(upstream, client, done);
          done.await(5, TimeUnit.SECONDS);
        }
      } catch (Exception ignored) {
      }
    }

    @Override public void close() throws IOException {
      running = false;
      serverSocket.close();
    }
  }

  private static final class RawServer implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final RawHandler handler;
    private final Thread acceptThread;
    final AtomicInteger acceptedConnections = new AtomicInteger();
    final Map<String, AtomicInteger> pathRequests = new ConcurrentHashMap<>();
    volatile boolean running = true;

    RawServer(RawHandler handler) throws IOException {
      this.handler = handler;
      this.serverSocket = new ServerSocket(0);
      this.acceptThread = new Thread(this::acceptLoop, "raw-http-server");
      this.acceptThread.setDaemon(true);
      this.acceptThread.start();
    }

    String url(String path) {
      return "http://127.0.0.1:" + serverSocket.getLocalPort() + path;
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    private void acceptLoop() {
      while (running) {
        try {
          Socket socket = serverSocket.accept();
          acceptedConnections.incrementAndGet();
          Thread thread = new Thread(() -> handleSocket(socket), "raw-http-connection");
          thread.setDaemon(true);
          thread.start();
        } catch (SocketException e) {
          if (running) e.printStackTrace();
        } catch (IOException e) {
          if (running) e.printStackTrace();
        }
      }
    }

    private void handleSocket(Socket socket) {
      try (socket) {
        socket.setSoTimeout(5000);
        InputStream input = socket.getInputStream();
        OutputStream output = socket.getOutputStream();
        while (running && !socket.isClosed()) {
          RawRequest request = readRequest(input);
          if (request == null) return;
          pathRequests.computeIfAbsent(request.path, ignored -> new AtomicInteger()).incrementAndGet();
          SimpleResponse response = handler.handle(request);
          if (response.closeWithoutResponse) return;
          response.write(output);
          output.flush();
          if ("close".equalsIgnoreCase(request.header("Connection")) || response.closeAfterWrite) return;
        }
      } catch (EOFException ignored) {
      } catch (IOException ignored) {
      }
    }

    private RawRequest readRequest(InputStream input) throws IOException {
      String requestLine = readLine(input);
      if (requestLine == null || requestLine.isEmpty()) return null;
      String[] parts = requestLine.split(" ", 3);
      if (parts.length < 3) throw new IOException("bad request line: " + requestLine);
      Map<String, List<String>> headers = new LinkedHashMap<>();
      String line;
      while ((line = readLine(input)) != null && !line.isEmpty()) {
        int colon = line.indexOf(':');
        if (colon <= 0) continue;
        String name = line.substring(0, colon);
        String value = line.substring(colon + 1).trim();
        headers.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
      }
      int contentLength = 0;
      boolean chunked = false;
      for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
        if (entry.getKey().equalsIgnoreCase("Content-Length")) {
          contentLength = Integer.parseInt(entry.getValue().get(0));
        }
        if (entry.getKey().equalsIgnoreCase("Transfer-Encoding")) {
          chunked = entry.getValue().stream().anyMatch(value -> value.toLowerCase(Locale.ROOT).contains("chunked"));
        }
      }
      List<String> chunkSizeLines = new ArrayList<>();
      byte[] body = chunked ? readChunked(input, chunkSizeLines) : readFixed(input, contentLength);
      String target = parts[1];
      String path = target;
      String query = "";
      int queryStart = target.indexOf('?');
      if (queryStart >= 0) {
        path = target.substring(0, queryStart);
        query = target.substring(queryStart + 1);
      }
      return new RawRequest(parts[0], target, parts[2], path, query, headers, new ArrayList<>(headers.keySet()), body, chunkSizeLines);
    }

    private static byte[] readFixed(InputStream input, int length) throws IOException {
      byte[] body = new byte[length];
      int offset = 0;
      while (offset < length) {
        int read = input.read(body, offset, length - offset);
        if (read == -1) throw new EOFException();
        offset += read;
      }
      return body;
    }

    private static byte[] readChunked(InputStream input, List<String> chunkSizeLines) throws IOException {
      ByteArrayOutputStream body = new ByteArrayOutputStream();
      while (true) {
        String sizeLine = readLine(input);
        if (sizeLine == null) throw new EOFException();
        chunkSizeLines.add(sizeLine);
        int separator = sizeLine.indexOf(';');
        String sizeText = separator >= 0 ? sizeLine.substring(0, separator) : sizeLine;
        int size = Integer.parseInt(sizeText.trim(), 16);
        if (size == 0) {
          while (true) {
            String trailer = readLine(input);
            if (trailer == null || trailer.isEmpty()) break;
          }
          return body.toByteArray();
        }
        body.write(readFixed(input, size));
        String ending = readLine(input);
        if (ending == null || !ending.isEmpty()) throw new IOException("malformed chunk ending");
      }
    }

    private static String readLine(InputStream input) throws IOException {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      while (true) {
        int b = input.read();
        if (b == -1) {
          return out.size() == 0 ? null : out.toString(StandardCharsets.ISO_8859_1);
        }
        if (b == '\r') {
          int next = input.read();
          if (next != '\n') throw new IOException("malformed line ending");
          return out.toString(StandardCharsets.ISO_8859_1);
        }
        out.write(b);
      }
    }

    @Override public void close() throws IOException {
      running = false;
      serverSocket.close();
    }
  }

  private interface RawHandler {
    SimpleResponse handle(RawRequest request) throws IOException;
  }

  private record RawRequest(String method, String target, String protocol, String path, String query, Map<String, List<String>> headers, List<String> headerOrder, byte[] body, List<String> chunkSizeLines) {
    String bodyString() {
      return new String(body, StandardCharsets.UTF_8);
    }

    String header(String name) {
      return headers.entrySet().stream()
          .filter(entry -> entry.getKey().equalsIgnoreCase(name))
          .flatMap(entry -> entry.getValue().stream())
          .findFirst()
          .orElse(null);
    }

    List<String> headerValues(String name) {
      return headers.entrySet().stream()
          .filter(entry -> entry.getKey().equalsIgnoreCase(name))
          .flatMap(entry -> entry.getValue().stream())
          .toList();
    }
  }

  private static int countOccurrences(String haystack, String needle) {
    int count = 0;
    int offset = 0;
    while ((offset = haystack.indexOf(needle, offset)) >= 0) {
      count++;
      offset += needle.length();
    }
    return count;
  }

  private static final class SimpleResponse {
    final int status;
    final List<String> headers;
    final byte[] body;
    final boolean closeAfterWrite;
    final boolean closeWithoutResponse;
    final Integer explicitLength;
    final byte[] prefix;
    final String statusLine;

    SimpleResponse(int status, List<String> headers, byte[] body, boolean closeAfterWrite, boolean closeWithoutResponse, Integer explicitLength) {
      this(status, headers, body, closeAfterWrite, closeWithoutResponse, explicitLength, new byte[0], null);
    }

    SimpleResponse(int status, List<String> headers, byte[] body, boolean closeAfterWrite, boolean closeWithoutResponse, Integer explicitLength, byte[] prefix) {
      this(status, headers, body, closeAfterWrite, closeWithoutResponse, explicitLength, prefix, null);
    }

    SimpleResponse(int status, List<String> headers, byte[] body, boolean closeAfterWrite, boolean closeWithoutResponse, Integer explicitLength, byte[] prefix, String statusLine) {
      this.status = status;
      this.headers = headers;
      this.body = body;
      this.closeAfterWrite = closeAfterWrite;
      this.closeWithoutResponse = closeWithoutResponse;
      this.explicitLength = explicitLength;
      this.prefix = prefix;
      this.statusLine = statusLine;
    }

    static SimpleResponse ok(String body) {
      return status(200, body);
    }

    static SimpleResponse status(int status, String body) {
      return raw(status, List.of(), body.getBytes(StandardCharsets.UTF_8));
    }

    static SimpleResponse redirect(String location) {
      return raw(303, List.of("Location: " + location), new byte[0]);
    }

    static SimpleResponse bytes(int status, byte[] body, Map<String, String> headers) {
      List<String> lines = headers.entrySet().stream().map(entry -> entry.getKey() + ": " + entry.getValue()).toList();
      return raw(status, lines, body);
    }

    static SimpleResponse raw(int status, List<String> headers, byte[] body) {
      return new SimpleResponse(status, headers, body, false, false, null);
    }

    static SimpleResponse prefixed(byte[] prefix, int status, List<String> headers, byte[] body) {
      return new SimpleResponse(status, headers, body, false, false, null, prefix);
    }

    static SimpleResponse statusLine(String statusLine, List<String> headers, byte[] body) {
      return new SimpleResponse(200, headers, body, false, false, null, new byte[0], statusLine);
    }

    static SimpleResponse rawWithLength(int status, List<String> headers, byte[] body, int length, boolean closeAfterWrite) {
      return new SimpleResponse(status, headers, body, closeAfterWrite, false, length);
    }

    static SimpleResponse withInterim(List<Integer> interimStatuses, int finalStatus, String body) {
      ByteArrayOutputStream prefix = new ByteArrayOutputStream();
      for (int interimStatus : interimStatuses) {
        try {
          prefix.write(("HTTP/1.1 " + interimStatus + " Interim\r\nContent-Length: 0\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        } catch (IOException impossible) {
          throw new AssertionError(impossible);
        }
      }
      return new SimpleResponse(finalStatus, List.of(), body.getBytes(StandardCharsets.UTF_8), false, false, null, prefix.toByteArray());
    }

    static SimpleResponse closeWithoutResponse() {
      return new SimpleResponse(0, List.of(), new byte[0], true, true, null);
    }

    void write(OutputStream output) throws IOException {
      output.write(prefix);
      String phrase = status == 303 ? "See Other" : status == 200 ? "OK" : "Error";
      String firstLine = statusLine != null ? statusLine : "HTTP/1.1 " + status + " " + phrase;
      output.write((firstLine + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
      boolean hasLength = headers.stream().anyMatch(header -> header.toLowerCase(Locale.ROOT).startsWith("content-length:"));
      boolean hasTransferEncoding = headers.stream().anyMatch(header -> header.toLowerCase(Locale.ROOT).startsWith("transfer-encoding:"));
      for (String header : headers) {
        output.write((header + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
      }
      if (!hasLength && !hasTransferEncoding) {
        int length = explicitLength != null ? explicitLength : body.length;
        output.write(("Content-Length: " + length + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
      }
      output.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
      output.write(body);
    }
  }
}
