package gov.ca.emsa.pulse.auth.user;

import gov.ca.emsa.pulse.auth.permission.GrantedPermission;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

public class JWTAuthenticatedUser implements User {

	private static final long serialVersionUID = 1L;
	private Long id;
	private String subjectName;
	private String firstName;
	private String lastName;
    private String email;
	private Set<GrantedPermission> permissions = new HashSet<GrantedPermission>();
	private boolean authenticated = true;
    private String jwt;

	public JWTAuthenticatedUser(){
		this.subjectName = null;
	}

	public JWTAuthenticatedUser(String subjectName) {
		this.subjectName = subjectName;
	}

	public String getSubjectName() {
		return subjectName;
	}

	public void setSubjectName(String subject) {
		this.subjectName = subject;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

	public Set<GrantedPermission> getPermissions() {
		return this.permissions;
	}

	public void addPermission(GrantedPermission permission){
		this.permissions.add(permission);
	}

	public void addPermission(String permissionValue) {
		GrantedPermission permission = new GrantedPermission(permissionValue);
		this.permissions.add(permission);
	}

	@Override
	public void removePermission(String permissionValue){
		this.permissions.remove(new GrantedPermission(permissionValue));
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.getPermissions();
	}

	@Override
	public Object getDetails() {
		return this;
	}

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
	public Object getPrincipal() {
		return this.getName();
	}

    @Override
	public Object getCredentials() {
		return this.getName();
	}

    @Override
	public String getPassword() {
		return "";
	}

	@Override
	public boolean isAuthenticated() {
		return this.authenticated;
	}

	@Override
	public void setAuthenticated(boolean arg0) throws IllegalArgumentException {
		this.authenticated = arg0;
	}

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

	@Override
	public String getName() {
		return subjectName;
	}

	@Override
	public String getUsername() {
		return subjectName;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

}
