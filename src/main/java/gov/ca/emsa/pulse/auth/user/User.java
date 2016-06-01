package gov.ca.emsa.pulse.auth.user;

import gov.ca.emsa.pulse.auth.permission.GrantedPermission;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public interface User extends UserDetails , Authentication {

	public Long getId();
	public String getSubjectName();
	public void setSubjectName(String subject);

	public void setFirstName(String firstName);
	public String getFirstName();
	public void setLastName(String lastName);
	public String getLastName();
    public void setEmail(String email);
    public String getEmail();

	public Set<GrantedPermission> getPermissions();
	public void addPermission(GrantedPermission permission);
	public void removePermission(String permissionValue);


	// UserDetails interface
	@Override
	public String getUsername();

	// Authentication Interface
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities();

	@Override
	public Object getDetails();

	@Override
	public Object getPrincipal();

	@Override
	public boolean isAuthenticated();

	@Override
	public void setAuthenticated(boolean arg0) throws IllegalArgumentException;

	@Override
	public String getName();

}
