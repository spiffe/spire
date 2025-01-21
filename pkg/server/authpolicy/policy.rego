package spire

# Query from the SPIRE Server is for the result variable.
#
# The fields of the result are the following:
# - `allow`: a boolean that if true, will authorize the call
# - `allow_if_local`: a boolean that if true, will authorize the call only if the
#   caller is a local UNIX socket call
# - `allow_if_admin`: a boolean that if true, will authorize the call only if the
#   caller has an admin SPIFFE ID
# - `allow_if_downstream`: a boolean that if true, will authorize the call
#   only if the caller has a downstream SPIFFE ID
# - `allow_if_agent`: a boolean that if true, will authorize the call only if
#   the caller is an agent

result = {
  "allow": allow, 
  "allow_if_admin": allow_if_admin,
  "allow_if_local": allow_if_local,
  "allow_if_downstream": allow_if_downstream,
  "allow_if_agent": allow_if_agent,
}


### DEFAULT POLICY START ###

default allow_if_admin = false
default allow_if_downstream = false
default allow_if_local = false
default allow_if_agent = false
default allow = false 


# Admin allow check
allow_if_admin = true if { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_admin
}

# Local allow check
allow_if_local = true if { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_local
}


# Downstream allow check
allow_if_downstream = true if { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_downstream
}


# Agent allow check
allow_if_agent = true if { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_agent
}

# Any allow check
allow = true if { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_any
}

### DEFAULT POLICY END  ###
