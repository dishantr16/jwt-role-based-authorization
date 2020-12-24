import {repository} from '@loopback/repository';
import {HttpErrors, post, requestBody} from '@loopback/rest';
import {promisify} from 'util';
import {Credentials, JWT_SECRET} from '../auth';
import {User} from '../models';
import {UserRepository, UserRoleRepository} from '../repositories';

const {sign} = require('jsonwebtoken');
const signAsync = promisify(sign);

export class UserController {
  constructor(
    @repository(UserRepository) private userRepository: UserRepository,
    @repository(UserRoleRepository) private userRoleRepository: UserRoleRepository,
  ) { }

  @post('/users')
  async createUser(@requestBody() user: User): Promise<User> {
    return await this.userRepository.create(user);
  }

  @post('/users/login')
  async login(@requestBody() credentials: Credentials) {
    if (!credentials.email || !credentials.password) throw new HttpErrors.BadRequest('Missing email or Password');
    const user = await this.userRepository.findOne({where: {email: credentials.email}});

    if (!user) throw new HttpErrors.Unauthorized('Invalid credentials');
    console.log("data");
    const isPasswordMatched = user.password === credentials.password;
    if (!isPasswordMatched) throw new HttpErrors.Unauthorized('Invalid credentials');

    const tokenObject = {email: credentials.email};
    const token = await signAsync(tokenObject, JWT_SECRET);
    const roles = await this.userRoleRepository.find({where: {userId: user.id}});
    const {id, email} = user;

    return {
      token,
      id: id as string,
      email,
      roles: roles.map(r => r.roleId),
    };
  }
}
