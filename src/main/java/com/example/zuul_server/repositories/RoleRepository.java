package com.example.zuul_server.repositories;

import com.example.zuul_server.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface RoleRepository extends MongoRepository<Role, String> {

	Role findByRole(String role);
}
