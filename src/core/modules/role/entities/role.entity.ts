import {
  Column,
  CreateDateColumn,
  Entity,
  JoinTable,
  ManyToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Permission } from '../../permission/entities/permission.entity';

@Entity()
export class Role {
  @PrimaryGeneratedColumn()
  id: string;

  @Column({
    length: 20,
  })
  name: string;

  @CreateDateColumn()
  createTime: Date;

  @UpdateDateColumn()
  updateTime: Date;

  // 与 Permission 表是多对多的关系
  @ManyToMany(() => Permission, { createForeignKeyConstraints: false })
  // 创建关联的中间表
  @JoinTable({
    name: 'role_permission_relation',
  })
  permissions: Permission[];
}
