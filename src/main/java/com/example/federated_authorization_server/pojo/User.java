package com.example.federated_authorization_server.pojo;

import java.io.Serializable;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

public class User implements Serializable, Cloneable{

    private final AtomicReference<String> id = new AtomicReference<>();
    private final AtomicReference<String>  name = new AtomicReference<>();;
    private final AtomicReference<String> password = new AtomicReference<>();;

    public User(String id, String name, String password) {
        this.id.set(id);
        this.name.set(name);
        this.password.set(password);
    }

    public User() {
        this.id.set(UUID.randomUUID().toString());
    }

    @Override
    public User clone(){
        User cloned = new User();
        cloned.replaceWith(this);
        return cloned;
    }

    public void replaceWith(User user) {
        this.id.set(user.getId());
        this.name.set(user.getName());
        this.password.set(user.getPassword());
    }

    public String getId() {
        return id.get();
    }

    public String getName() {
        return name.get();
    }


    public String getPassword() {
        return password.get();
    }


    @Override
    public String toString() {
        return "Server{" +
                "id=" + id +
                ", name=" + name +
                ", ApiKey=" + password +
                '}';
    }
}
