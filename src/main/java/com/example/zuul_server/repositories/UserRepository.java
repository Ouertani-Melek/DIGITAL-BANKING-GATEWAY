package com.example.zuul_server.repositories;

import com.example.zuul_server.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRepository extends MongoRepository<User, String> {

	User findByEmail(String email);
}
