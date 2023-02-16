package com.bgtkv.statelessoauthclient.oauth.model

enum class AuthenticationStatus(
    val status: String
) {
    SUCCESS("Success"),
    FAILURE("Failure"),
    ACCESS_DENIED("Access denied");
}