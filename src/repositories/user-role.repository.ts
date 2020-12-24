import {DefaultCrudRepository} from '@loopback/repository';
import {UserRole, UserRoleRelations} from '../models';
import {RolebaseddbDataSource} from '../datasources';
import {inject} from '@loopback/core';

export class UserRoleRepository extends DefaultCrudRepository<
  UserRole,
  typeof UserRole.prototype.id,
  UserRoleRelations
> {
  constructor(
    @inject('datasources.rolebaseddb') dataSource: RolebaseddbDataSource,
  ) {
    super(UserRole, dataSource);
  }
}
