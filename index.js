'use strict';

var _ = require('underscore');

function getScope(rbac, cb) {
	var permissions = this.permissions || [];

	rbac.getScope(this.role, function(err, scope) {
		if(err) {
			return cb(err);
		}

		scope = _.union(permissions, scope);
		cb(null, scope);
	});

	return this;
}

/**
 * Check if user has assigned a specific permission 
 * @param  {RBAC}  rbac Instance of RBAC
 * @param  {String}   action  Name of action 
 * @param  {String}   resource  Name of resource 
 * @return {Boolean}        
 */
function can(rbac, action, resource, cb) {
	var _this = this;

	//check existance of permission
	rbac.getPermission(action, resource, function(err, permission) {
		if(err) {
			return cb(err);
		}

		if(!permission) {
			return cb(null, false);
		}

		//check user additional permissions
		if(_.indexOf(_this.permissions, permission.getName()) !== -1) {
			return cb(null, true);
		}

		if(!_this.role) {
			return cb(null, false);	
		}

		//check permission inside user role
		rbac.can(_this.role, action, resource, cb);
	});

	return this;
}

/**
 * Assign additional permissions to the user
 * @param  {String|Array}   permissions  Array of permissions or string representing of permission
 * @param  {Function} cb Callback
 */
function addPermission(rbac, action, resource, cb) {
	var _this = this;

	rbac.getPermission(action, resource, function(err, permission) {
		if(err) {
			return cb(err);
		}	

		if(!permission) {
			return cb(new Error('Permission not exists'));
		}

		if(_.indexOf(_this.permissions, permission.getName()) !== -1) {
			return cb(new Error('Permission is already assigned'));
		}

		_this.permissions.push(permission.getName());
		_this.save(function(err, user) {
			if(err) {
				return cb(err);
			}

			if(!user) {
				return cb(new Error('User is undefined'));	
			}

			cb(null, true);
		});
	});

	return this;
}

function removePermission(permissionName, cb) {
	if(_.indexOf(this.permissions, permissionName) === -1) {
		return cb(new Error('Permission was not asssigned'));
	}

	this.permissions = _.without(this.permissions, permissionName);
	this.save(function(err, user) {
		if(err) {
			return cb(err);
		}

		if(!user) {
			return cb(new Error('User is undefined'));
		}

		if(_.indexOf(user.permissions, permissionName) !== -1) {
			return cb(new Error('Permission was not removed'));
		}

		cb(null, true);
	});

	return this;
}

function removePermissionFromCollection(permissionName, cb) {
	this.update({
		permissions: permissionName
	}, {
		$pull: {
			permissions: permissionName
		}
	}, { multi: true }, function(err, num) {
		if(err) {
			return cb(err);
		}

        return cb(null, true);
    });

	return this;
}

/**
 * Check if user has assigned a specific role 
 * @param  {RBAC}  rbac Instance of RBAC
 * @param  {String}  name Name of role
 * @return {Boolean}      [description]
 */
function hasRole(rbac, role, cb) {
	if(!this.role) {
		return cb(null, false);
	}

	//check existance of permission
	rbac.hasRole(this.role, role, cb);
	return this;
}

function removeRole(cb) {
	if(!this.role) {
		return cb(null, false);
	}

	this.role = null;
	this.save(function(err, user) {
		if(err) {
			return cb(err);
		}

		if(!user) {
			return cb(new Error('User is undefined'));
		}

		cb(null, user.role === null);
	});

	return this;
}

function removeRoleFromCollection(roleName, cb) {
	this.update({
		role: roleName
	}, {
		role: null
	}, { multi: true }, function(err, num) {
		if(err) {
			return cb(err);
		}

        return cb(null, true);
    });

	return this;
}

function setRole(rbac, role, cb) {
	var _this = this;

	if(this.role === role) {
		return cb(new Error('User already has assigned this role'));
	}

	//check existance of permission
	rbac.getRole(role, function(err, role) {
		if(err) {
			return cb(err);
		}

		if(!role) {
			return cb(new Error('Role does not exists'));		
		}

		_this.role = role.getName();
		_this.save(function(err, user) {
			if(err) {
				return cb(err);
			}

			if(!user) {
				return cb(new Error('User is undefined'));
			}

			cb(null, user.role === _this.role);
		});
	});
}

module.exports = function hrbacPlugin (schema, options) {
	options = options || {};

	schema.add({
		role        : { type: String },
		permissions : { type: [String] }
	});

	schema.methods.can = can;

	schema.methods.addPermission = addPermission;
	schema.methods.removePermission = removePermission;

	schema.methods.hasRole = hasRole;
	schema.methods.removeRole = removeRole;
	schema.methods.setRole = setRole;

	schema.methods.getScope = getScope;

	schema.statics.removeRoleFromCollection = removeRoleFromCollection;
	schema.statics.removePermissionFromCollection = removePermissionFromCollection;
};