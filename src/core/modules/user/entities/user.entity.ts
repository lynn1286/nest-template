import {
  BeforeInsert,
  Column,
  Entity,
  JoinTable,
  ManyToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import * as crypto from 'crypto';
import encry from '@/common/utils/crypto.util';
import { Role } from '../../role/entities/role.entity';

@Entity('user')
export class User {
  /** 插入前处理加盐操作 */
  @BeforeInsert()
  beforeInsert() {
    this.salt = crypto.randomBytes(4).toString('base64');
    this.password = encry(this.password, this.salt);
  }

  @PrimaryGeneratedColumn('uuid')
  id: number;

  @Column({ length: 30 })
  username: string;

  @Column({ nullable: true })
  nickname: string;

  @Column()
  password: string;

  @Column({ nullable: true })
  avatar: string;

  @Column({ nullable: true })
  email: string;

  @Column({ nullable: true })
  salt: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  create_time: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  update_time: Date;

  @ManyToMany(() => Role, { createForeignKeyConstraints: false })
  @JoinTable({
    name: 'user_role_relation',
  })
  roles: Role[];
}
