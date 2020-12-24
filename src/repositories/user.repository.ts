import {DefaultCrudRepository} from '@loopback/repository';
import {User, UserRelations} from '../models';
import {RolebaseddbDataSource} from '../datasources';
import {inject} from '@loopback/core';

export class UserRepository extends DefaultCrudRepository<
  User,
  typeof User.prototype.id,
  UserRelations
> {
  constructor(
    @inject('datasources.rolebaseddb') dataSource: RolebaseddbDataSource,
  ) {
    super(User, dataSource);
  }
}
