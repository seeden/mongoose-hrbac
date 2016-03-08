import union from 'lodash/union';
import indexOf from 'lodash/indexOf';
import without from 'lodash/without';

function getScope(rbac, cb) {
  const permissions = this.permissions || [];

  rbac.getScope(this.role, (err, scope) => {
    if (err) {
      return cb(err);
    }

    const newScope = union(permissions, scope);
    return cb(null, newScope);
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
  // check existance of permission
  rbac.getPermission(action, resource, (err, permission) => {
    if (err) {
      return cb(err);
    }

    if (!permission) {
      return cb(null, false);
    }

    // check user additional permissions
    if (indexOf(this.permissions, permission.name) !== -1) {
      return cb(null, true);
    }

    if (!this.role) {
      return cb(null, false);
    }

    // check permission inside user role
    return rbac.can(this.role, action, resource, cb);
  });

  return this;
}

/**
 * Assign additional permissions to the user
 * @param  {String|Array}   permissions  Array of permissions or string representing of permission
 * @param  {Function} cb Callback
 */
function addPermission(rbac, action, resource, cb) {
  rbac.getPermission(action, resource, (err, permission) => {
    if (err) {
      return cb(err);
    }

    if (!permission) {
      return cb(new Error('Permission not exists'));
    }

    if (indexOf(this.permissions, permission.name) !== -1) {
      return cb(new Error('Permission is already assigned'));
    }

    this.permissions.push(permission.name);
    return this.save((err2, user) => {
      if (err2) {
        return cb(err2);
      }

      if (!user) {
        return cb(new Error('User is undefined'));
      }

      return cb(null, true);
    });
  });

  return this;
}

function removePermission(permissionName, cb) {
  if (indexOf(this.permissions, permissionName) === -1) {
    cb(new Error('Permission was not asssigned'));
    return this;
  }

  this.permissions = without(this.permissions, permissionName);
  this.save((err, user) => {
    if (err) {
      return cb(err);
    }

    if (!user) {
      return cb(new Error('User is undefined'));
    }

    if (indexOf(user.permissions, permissionName) !== -1) {
      return cb(new Error('Permission was not removed'));
    }

    return cb(null, true);
  });

  return this;
}

function removePermissionFromCollection(permissionName, cb) {
  this.update({
    permissions: permissionName,
  }, {
    $pull: {
      permissions: permissionName,
    },
  }, {
    multi: true,
  }, (err, num) => {
    if (err) {
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
  if (!this.role) {
    cb(null, false);
    return this;
  }

  // check existance of permission
  rbac.hasRole(this.role, role, cb);
  return this;
}

function removeRole(cb) {
  if (!this.role) {
    cb(null, false);
    return this;
  }

  this.role = null;
  this.save((err, user) => {
    if (err) {
      return cb(err);
    }

    if (!user) {
      return cb(new Error('User is undefined'));
    }

    return cb(null, user.role === null);
  });

  return this;
}

function removeRoleFromCollection(roleName, cb) {
  this.update({
    role: roleName,
  }, {
    role: null,
  }, {
    multi: true,
  }, (err, num) => {
    if (err) {
      return cb(err);
    }

    return cb(null, true);
  });

  return this;
}

function setRole(rbac, role, cb) {
  if (this.role === role) {
    cb(new Error('User already has assigned this role'));
    return this;
  }

  // check existance of permission
  rbac.getRole(role, (err, role) => {
    if (err) {
      return cb(err);
    }

    if (!role) {
      return cb(new Error('Role does not exists'));
    }

    this.role = role.name;
    return this.save((err2, user) => {
      if (err2) {
        return cb(err2);
      }

      if (!user) {
        return cb(new Error('User is undefined'));
      }

      return cb(null, user.role === this.role);
    });
  });

  return this;
}

export default function hrbacPlugin(schema, options = {}) {
  schema.add({
    role: {
      type: String,
      default: options.defaultRole,
    },
    permissions: {
      type: [String],
      default: options.defaultPermissions,
    },
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
}
