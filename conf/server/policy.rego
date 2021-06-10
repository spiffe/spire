package spire

# Result contains two fields:
#
# allow - the API call should be allowed
#
# By default each "api" object has several flags:
#
# allow_any:bool - if true, sets allow to true
# allow_admin:bool - if true, allows the call if input.admin is true
# allow_localn:bool - if true, allows the call if input.local is true
# allow_downstream:bool - if true, allows the call if input.downstream is true


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
allow_if_admin = true { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_admin
    #input.admin
}

# Local allow check
allow_if_local = true { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_local
    # input.local
}


# Downstream allow check
allow_if_downstream = true { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_downstream
    #input.admin
}


# Agent allow check
allow_if_agent = true { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_agent
    #input.admin
}

# Any allow check
allow = true { 
    r := data.apis[_]
    r.full_method == input.full_method 
    
    r.allow_any
}

### DEFAULT POLICY ENDSTART  ###
