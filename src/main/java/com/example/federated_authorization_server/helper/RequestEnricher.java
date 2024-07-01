package com.example.federated_authorization_server.helper;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class RequestEnricher extends HttpServletRequestWrapper {

    public RequestEnricher(ServletRequest target) {
        super((HttpServletRequest) target);
    }

    public RequestEnricher addOnUnauthorizedAction(Consumer<HttpServletResponse> action) {
        getActions().add(action);
        return this;
    }

    @SuppressWarnings("unchecked")
    private List<Consumer<HttpServletResponse>> getActions() {
        Object field = getRequest().getAttribute("onUnauthorizedActions");
        List<Consumer<HttpServletResponse>> actions;
        if (field == null) {
            actions = new ArrayList<>();
            getRequest().setAttribute("onUnauthorizedActions", actions);
        } else {
            actions = (List<Consumer<HttpServletResponse>>) field;
        }
        return actions;
    }

    public void applyOnUnauthorizedActions(ServletResponse response) {
        HttpServletResponse resp = (HttpServletResponse) response;
        getActions().forEach(a -> a.accept(resp));
    }
}
