package com.bgtkv.statelessoauthclient

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class StatelessOauthClientApplication

fun main(args: Array<String>) {
    runApplication<StatelessOauthClientApplication>(*args)
}
