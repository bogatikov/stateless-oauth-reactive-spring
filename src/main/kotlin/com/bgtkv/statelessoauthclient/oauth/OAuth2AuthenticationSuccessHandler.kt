package com.bgtkv.statelessoauthclient.oauth

import com.bgtkv.statelessoauthclient.oauth.model.AuthenticationPayload
import com.bgtkv.statelessoauthclient.oauth.model.AuthenticationStatus
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.Logger
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

@Component
class OAuth2AuthenticationSuccessHandler(
    val objectMapper: ObjectMapper,
    val logger: Logger
) : ServerAuthenticationSuccessHandler {
    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange,
        authentication: Authentication
    ): Mono<Void> {
        logger.info("In success handler $authentication")
        val payload = objectMapper
            .writeValueAsString(
                AuthenticationPayload(AuthenticationStatus.SUCCESS.status)
            )
        val response = webFilterExchange.exchange.response
        val buffer = response.bufferFactory().wrap(payload.toByteArray())
        response.statusCode = HttpStatus.OK
        response.headers.contentType = MediaType.APPLICATION_JSON

        return response.writeWith(Flux.just(buffer))
    }
}
