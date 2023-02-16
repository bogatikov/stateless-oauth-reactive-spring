package com.bgtkv.statelessoauthclient.oauth

import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

@Component
class CustomRedirectFilter(
    val customStatelessAuthorizationRequestResolver: CustomStatelessAuthorizationRequestResolver,
    val customStatelessAuthorizationRequestRepository: CustomStatelessAuthorizationRequestRepository,
    val jsonServerRedirectStrategy: ServerRedirectStrategy
) : WebFilter {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        return customStatelessAuthorizationRequestResolver.resolve(exchange)
            .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
            .onErrorResume(ClientAuthorizationRequiredException::class.java) { ex ->
                customStatelessAuthorizationRequestResolver.resolve(exchange, ex.clientRegistrationId)
            }
            .flatMap { handleAuth(exchange, it) }
    }

    fun handleAuth(exchange: ServerWebExchange, authorizationRequest: OAuth2AuthorizationRequest): Mono<Void> {
        return Mono.defer {
            var saveAuthorizationRequest =
                Mono.empty<Void>()
            if (AuthorizationGrantType.AUTHORIZATION_CODE == authorizationRequest.grantType) {
                saveAuthorizationRequest = this.customStatelessAuthorizationRequestRepository
                    .saveAuthorizationRequest(authorizationRequest, exchange)
            }

            val redirectUri =
                UriComponentsBuilder.fromUriString(authorizationRequest.authorizationRequestUri)
                    .build(true)
                    .toUri()

            saveAuthorizationRequest
                .then(jsonServerRedirectStrategy.sendRedirect(exchange, redirectUri))
        }
    }
}