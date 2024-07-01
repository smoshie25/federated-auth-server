package com.example.federated_authorization_server.security;

import com.example.federated_authorization_server.pojo.User;
import org.apache.logging.log4j.ThreadContext;

import java.util.Map;
import java.util.function.Supplier;

public class SecurityContext {

    private final User user;


    public SecurityContext(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    public void runInContextOf(User userObject, Runnable runnable) {
        try {
            callInContextOf(userObject, () -> {
                runnable.run();
                return null;
            });
        } catch (Exception e) {
            throw (RuntimeException) e;
        }
    }

    public <V> V callInContextOf(User userObject, Supplier<V> supplier) {
        User existingSubject = userObject.clone();
        Map<String, String> existingThreadContext = ThreadContext.getImmutableContext();
        user.replaceWith(userObject);
        ThreadContext.put("CORRELATION_ID", user.getId());
        ThreadContext.put("USER", user.getName());
        try {
            return supplier.get();
        } finally {
            user.replaceWith(existingSubject);
            ThreadContext.clearMap();
            ThreadContext.putAll(existingThreadContext);
        }
    }
}
