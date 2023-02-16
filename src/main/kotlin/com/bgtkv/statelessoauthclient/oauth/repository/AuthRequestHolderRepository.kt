package com.bgtkv.statelessoauthclient.oauth.repository

import com.bgtkv.statelessoauthclient.oauth.model.AuthRequestHolder
import org.springframework.stereotype.Repository
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.toMono
import java.util.*
import java.util.concurrent.ConcurrentHashMap

@Repository
//TODO replace with real DB repository
class AuthRequestHolderRepository {
    private val holder = ConcurrentHashMap<UUID, AuthRequestHolder>()
    fun findById(id: UUID): Mono<AuthRequestHolder> {
        return Mono.justOrEmpty(holder[id])
    }

    fun save(authRequestHolder: AuthRequestHolder): Mono<AuthRequestHolder> {
        holder[authRequestHolder.id] = authRequestHolder
        return authRequestHolder.toMono()
    }

    fun remove(id: UUID): Mono<Void> {
        holder.remove(id)
        return Mono.empty()
    }
}