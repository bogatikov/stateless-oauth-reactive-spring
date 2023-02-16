package com.bgtkv.statelessoauthclient.oauth

import com.bgtkv.statelessoauthclient.oauth.model.AuthRequestHolder
import com.bgtkv.statelessoauthclient.oauth.repository.AuthRequestHolderRepository
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component
import org.springframework.util.SerializationUtils
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.util.*

@Component
class CustomStatelessAuthorizationRequestRepository(
    val authRequestHolderRepository: AuthRequestHolderRepository
) : ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    companion object {
        private const val AUTH_ID_HEADER = "Auth-Identification"
        private val B64E: Base64.Encoder = Base64.getEncoder()
        private val B64D: Base64.Decoder = Base64.getDecoder()
    }

    override fun loadAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        val authId = exchange.request.headers.getFirst(AUTH_ID_HEADER) ?: return Mono.empty()
        return authRequestHolderRepository.findById(UUID.fromString(authId))
            .map { holder ->
                decrypt(holder.payload)
            }
    }

    override fun removeAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        val authId = exchange.request.headers.getFirst(AUTH_ID_HEADER) ?: return Mono.empty()
        return authRequestHolderRepository.findById(UUID.fromString(authId))
            .flatMap { holder ->
                authRequestHolderRepository.remove(holder.id)
                    .thenReturn(decrypt(holder.payload))
            }
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?,
        exchange: ServerWebExchange
    ): Mono<Void> {

        return if (authorizationRequest == null) {
            exchange.response.headers.remove(AUTH_ID_HEADER)
            Mono.empty()
        } else {
            val authRequestHolder = AuthRequestHolder(
                UUID.randomUUID(),
                encrypt(authorizationRequest)
            )
            exchange.response.headers[AUTH_ID_HEADER] = listOf(authRequestHolder.id.toString())
            authRequestHolderRepository.save(authRequestHolder)
                .then()
        }
    }

    private fun encrypt(authorizationRequest: OAuth2AuthorizationRequest): String {
        val bytes: ByteArray? = SerializationUtils.serialize(authorizationRequest)
        return B64E.encodeToString(bytes)
    }

    private fun decrypt(encrypted: String): OAuth2AuthorizationRequest {
        val encryptedBytes: ByteArray = B64D.decode(encrypted)
        return SerializationUtils.deserialize(encryptedBytes) as OAuth2AuthorizationRequest
    }
}