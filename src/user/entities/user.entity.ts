import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('user')
export class User {
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
  role: string;

  @Column({ nullable: true })
  salt: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  create_time: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  update_time: Date;
}
