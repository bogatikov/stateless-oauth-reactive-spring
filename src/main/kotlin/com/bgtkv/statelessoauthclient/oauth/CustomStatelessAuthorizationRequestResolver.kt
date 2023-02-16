package com.bgtkv.statelessoauthclient.oauth

import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class CustomStatelessAuthorizationRequestResolver(
    clientRegistrationRepository: ReactiveClientRegistrationRepository
) : ServerOAuth2AuthorizationRequestResolver {

    private val delegate: ServerOAuth2AuthorizationRequestResolver

    init {
        delegate = DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository)
    }

    override fun resolve(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        return delegate.resolve(exchange)
    }

    override fun resolve(
        exchange: ServerWebExchange?,
        clientRegistrationId: String?
    ): Mono<OAuth2AuthorizationRequest> {
        return delegate.resolve(exchange, clientRegistrationId)
    }
}