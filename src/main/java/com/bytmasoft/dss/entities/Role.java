package com.bytmasoft.dss.entities;


import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * Hierarchical Roles
 */

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "roles")
public class Role implements Serializable {

@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
@Column(name = "id", nullable = false)
private Long id;


@Builder.Default
@OneToMany(mappedBy = "parentRole", cascade = CascadeType.ALL, orphanRemoval = true)
private Set<Role> childRoles = new HashSet<>();

@ManyToOne
@JoinColumn(name = "parent_role_id")
private Role parentRole;

@Column(unique = true, nullable = false)
private String name;


private LocalDateTime addedOn;


private LocalDateTime modifiedOn;

private boolean isActive;


private boolean deleted;

private String addedBy;

private String modifiedBy;

@Builder.Default
@ManyToMany(fetch = FetchType.EAGER)
@JoinTable(
		name = "role_permissions",
		joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"),
		inverseJoinColumns = @JoinColumn(name = "permission_id", referencedColumnName = "id"))
private Set<Permission> permissions = new HashSet<>();

}
