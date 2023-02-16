package com.bgtkv.statelessoauthclient.config

import com.bgtkv.statelessoauthclient.oauth.*
import com.bgtkv.statelessoauthclient.oauth.model.AuthenticationPayload
import com.bgtkv.statelessoauthclient.oauth.model.AuthenticationStatus
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.security.web.server.SecurityWebFilterChain
import reactor.core.publisher.Flux

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class SecurityConfig(
    val customStatelessAuthorizationRequestRepository: CustomStatelessAuthorizationRequestRepository,
    val customStatelessAuthorizationRequestResolver: CustomStatelessAuthorizationRequestResolver,
    val customAuthorizedClientService: ReactiveOAuth2AuthorizedClientService,
    val oAuth2AuthenticationSuccessHandler: OAuth2AuthenticationSuccessHandler,
    val oAuth2AuthenticationFailureHandler: OAuth2AuthenticationFailureHandler,
    val customRedirectFilter: CustomRedirectFilter,
    val objectMapper: ObjectMapper
) {

    @Bean
    fun securityWebFilterChain(httpSecurity: ServerHttpSecurity): SecurityWebFilterChain {
        return httpSecurity
            .csrf().disable()
            .cors().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .authorizeExchange()
            .pathMatchers("/login/oauth2/code/**").permitAll()
            .anyExchange().authenticated()
            .and()
            .oauth2Login {
                it.authorizationRequestRepository(customStatelessAuthorizationRequestRepository)
                it.authorizationRequestResolver(customStatelessAuthorizationRequestResolver)
                it.authorizedClientService(customAuthorizedClientService)
                it.authenticationSuccessHandler(oAuth2AuthenticationSuccessHandler)
                it.authenticationFailureHandler(oAuth2AuthenticationFailureHandler)
            }
            .exceptionHandling {
                it.accessDeniedHandler { exchange, _ ->
                    val payload = objectMapper
                        .writeValueAsString(
                            AuthenticationPayload(AuthenticationStatus.ACCESS_DENIED.status)
                        )
                    val response = exchange.response
                    response.headers.contentType = MediaType.APPLICATION_JSON
                    response.writeWith(
                        Flux.just(
                            response.bufferFactory().wrap(payload.toByteArray())
                        )
                    )
                }
                it.authenticationEntryPoint { exchange, _ ->
                    val payload = objectMapper
                        .writeValueAsString(
                            AuthenticationPayload(AuthenticationStatus.ACCESS_DENIED.status)
                        )
                    val response = exchange.response
                    response.headers.contentType = MediaType.APPLICATION_JSON
                    response.writeWith(
                        Flux.just(
                            response.bufferFactory().wrap(payload.toByteArray())
                        )
                    )
                }
            }
            .addFilterAt(customRedirectFilter, SecurityWebFiltersOrder.HTTP_BASIC)
            .build()
    }
}
