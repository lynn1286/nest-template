# NestJS 项目

[![NestJS](https://img.shields.io/badge/NestJS-v8.0.0-green.svg)](https://nestjs.com) [![Typescript](https://img.shields.io/badge/Typescript-v5.0.0-white.svg)](https://www.typescriptlang.org/) [![npm](https://img.shields.io/badge/npm-v8.0.0-blue.svg)](https://www.npmjs.com/) [![node](https://img.shields.io/badge/node-v16.15.0-bluegreen.svg)](https://nodejs.org/en)



## `config` 全局配置

安装依赖：
```BASH
npm i @nestjs/config
npm i js-yaml  
npm i -D @types/js-yaml
```

在`src/config`目录下新建以下文件：
```BASH
config                
├─ config.dev.yaml    
├─ config.local.yaml  
├─ config.prod.yaml   
└─ index.ts   
```
`yaml` 环境配置文件内容：
```BASH
http:
  host: "localhost"
  port: 3000

db:
  mysql:
    url: "localhost"
    port: 3306
    database: "yaml-db"
```
`index.ts` 文件内容：
```JS
import { registerAs } from '@nestjs/config';
import { readFileSync } from 'fs';
import * as yaml from 'js-yaml';
import { join } from 'path';

const YAML_CONFIG_FILENAME = {
  dev: 'config.dev.yaml',
  prod: 'config.prod.yaml',
  local: 'config.local.yaml',
};

/**
 * @description: 全局配置 - 命名空间 globalConfig
 */
export default registerAs('globalConfig', () => {
  const env = process.env.NODE_ENV;

  return yaml.load(
    readFileSync(
      join(
        __dirname,
        env ? YAML_CONFIG_FILENAME[env] : YAML_CONFIG_FILENAME['local'],
      ),
      'utf8',
    ),
  ) as Record<string, any>;
});
```
修改`nest-cli.json`文件内容：
```json
{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true,
    "assets": ["**/*.yaml"], // 复制静态 yaml 文件到dist目录
    "watchAssets": true // 监听静态文件的更改
  },
  "generateOptions": {
    "spec": false // cli 不生成测试文件
  }
}
```

增加`global.d.ts`文件，给`Process`增加类型：
```JS
declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: string;
  }
}
```
在`app.module.ts`文件中导入：
```JS
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import configurationYaml from './config/index';

@Module({
  imports: [
    // config 配置
    ConfigModule.forRoot({
      cache: true, // 开启缓存
      load: [configurationYaml],
      isGlobal: true, // 注册成全局模块
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```
测试下：
```JS
import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    // 依赖注入
    private readonly configService: ConfigService,
  ) {}

  @Get()
  getHello(): string {
    console.log(this.configService.get('globalConfig.http.port')); // 3000
    console.log(this.configService.get('globalConfig.db')); // { mysql: { url: 'localhost', port: 3306, database: 'yaml-db' } }

    return this.appService.getHello();
  }
}
```

局部使用配置文件：
```JS
// database.module.ts
import databaseConfig from './config/database.config';

@Module({
  // 在需要的模块中使用配置文件
  imports: [ConfigModule.forFeature(databaseConfig)],
})
export class DatabaseModule {}

```



## `mysql` 配置

安装：
```BASH
npm i @nestjs/typeorm typeorm mysql2
```

在`app.module.ts`文件下进行模块导入：
```JS
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import configurationYaml from './config/index';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    ConfigModule.forRoot({
      cache: true,
      load: [configurationYaml],
      isGlobal: true,
    }),

    // 使用 typeorm 动态模块注册，传入全局配置
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        // 读取全局配置下的mysql配置
        return configService.get('GLOBAL_CONFIG.db.mysql');
      },
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```



## 统一的`Filter`异常处理器

新建文件：

```bash
nest g filter core/filter/http.exception
```

修改文件`http.exception.filter.ts`内容：

```typescript
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { APIException } from './api.exception.filter';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(paramException: HttpException, paramHost: ArgumentsHost) {
    const ctx = paramHost.switchToHttp();
    const response = ctx.getResponse() as Response;
    const request = ctx.getRequest() as Request;

    const message = paramException.message;

    let retCode = ErrorCodeEnum.FAIL;
    let status = HttpStatus.OK;

    if (paramException instanceof APIException) {
      retCode = (paramException as APIException).getErrorCode();
    } else if (paramException instanceof HttpException) {
      status = (paramException as HttpException).getStatus();
    } else {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
    }

    const errorResponse = {
      /** 错误消息 */
      msg: message,
      /** 业务状态码 */
      code: retCode,
      /** http 状态码 */
      statusCode: status,
      /** 当前请求路由 */
      url: request.originalUrl,
    };

    // 设置返回的状态码、请求头、发送错误信息
    response.status(HttpStatus.OK);
    response.header('Content-Type', 'application/json; charset=utf-8');
    response.send(errorResponse);
  }
}
```

接着在同目录下新建`api.exception.filter.ts`:

```typescript
import { HttpException, HttpStatus } from '@nestjs/common';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';

/**
 * @description: 自定义 Exception 增加业务状态码响应
 * @return {*}
 */
export class APIException extends HttpException {
  private errorMessage: string;
  private errorCode: ErrorCodeEnum;

  constructor(
    errorMessage: string,
    errorCode: ErrorCodeEnum,
    statusCode: HttpStatus = HttpStatus.OK,
  ) {
    super(errorMessage, statusCode);
    this.errorMessage = errorMessage;
    this.errorCode = errorCode;
  }

  getErrorCode(): ErrorCodeEnum {
    return this.errorCode;
  }

  getErrorMessage(): string {
    return this.errorMessage;
  }
}
```

接着创建`error.code.enum.ts`文件：

```typescript
/**
 * @description: 定义业务请求状态码
 * @return {*}
 */
export enum ErrorCodeEnum {
  /** 请求成功 */
  SUCCESS = 0,
  /** 系统错误 */
  FAIL = 1,
  /** 系统繁忙 */
  TIMEOUT = -1,

  /** 用户已存在 */
  USER_EXIST = 1000,
  /** 请求参数校验失败 */
  QUERY_PARAM_INVALID_FAIL = 1001,
}
```

注册成全局`Filter`异常处理器：

```typescript
@Module({
  imports: [
    ConfigModule.forRoot({
      cache: true,
      load: [configurationYaml],
      isGlobal: true,
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return configService.get('GLOBAL_CONFIG.db.mysql');
      },
    }),
    UserModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    AppService,
  ],
})
export class AppModule {}
```



## 返回格式化拦截器(`interceptor`)

创建文件：

```
nest g interceptor core/interceptor/transform
```

修改`transform.interceptor.ts`文件：

```typescript
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';
import { Response, Request } from 'express';
import { Reflector } from '@nestjs/core';

export interface IResponse<T> {
  data: T;
}

/** 每次请求的记数器 */
let requestSeq = 0;

@Injectable()
export class TransformInterceptor implements NestInterceptor {
  private readonly logger = new Logger(TransformInterceptor.name);

  constructor(private reflector: Reflector) {}

  intercept(
    paramContext: ExecutionContext,
    paramNext: CallHandler,
  ): Observable<any> {
    /** 请求开始时间 */
    const start = Date.now();
    /** 当前环境 */
    const host = paramContext.switchToHttp();
    /** 请求对象 */
    const req = host.getRequest<Request>();
    /** 响应对象 */
    const res = host.getResponse<Response>();
    /** 当前计数 */
    const seq = requestSeq++;
    /** 当前URL */
    const url = req.url; // req.path;
    /** 当前URL */
    const urlInfo = `${req.method} ${url}`;

    this.logger.log(`Incoming request: [第${seq}次] ==> ${urlInfo}`);
    req['seq'] = seq;

    return paramNext
      .handle()
      .pipe(
        map((data) => {
          /* 这里拦截POST返回的statusCode，它默认返回是201, 这里改为200 */
          if (res.statusCode === HttpStatus.CREATED && req.method === 'POST') {
            res.statusCode = HttpStatus.OK;
          }

          return {
            /** 成功消息 */
            msg: '请求成功',
            /** 业务状态码 */
            code: ErrorCodeEnum.SUCCESS,
            /** http 状态码 */
            statusCode: res.statusCode,
            /** 请求的数据 */
            data,
          };
        }),
      )
      .pipe(
        // 这里打印请求处理完成的信息
        tap(() =>
          this.logger.log(
            `Response request: [第${seq}次] <== ${urlInfo} ${
              Date.now() - start
            } ms`,
          ),
        ),
      );
  }
}

```

注册成全局拦截器(`interceptor`)：

```typescript
@Module({
  imports: [
    ConfigModule.forRoot({
      cache: true,
      load: [configurationYaml],
      isGlobal: true,
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return configService.get('GLOBAL_CONFIG.db.mysql');
      },
    }),
    UserModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor,
    },
    AppService,
  ],
})
export class AppModule {}

```



## 格式化`DTO`参数校验

创建文件：

```
nest g pipe /core/pipes/validation
```

修改`validation.pipe.ts`：

```typescript
import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { ValidationError, validate } from 'class-validator';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';
import { APIException } from 'src/core/filter/http.exception/api.exception.filter';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(
    paramValue: any,
    { metatype: paramMetaType }: ArgumentMetadata,
  ) {
    if (!paramMetaType || !this.toValidate(paramMetaType)) {
      return paramValue;
    }
    const object = plainToClass(paramMetaType, paramValue);
    const errors = await validate(object);
    const errorList: string[] = [];
    const errObjList: ValidationError[] = [...errors];

    do {
      const e = errObjList.shift();
      if (!e) {
        break;
      }
      if (e.constraints) {
        for (const item in e.constraints) {
          errorList.push(e.constraints[item]);
        }
      }
      if (e.children) {
        errObjList.push(...e.children);
      }
    } while (true);
    if (errorList.length > 0) {
      throw new APIException(
        '请求参数校验错误:' + errorList.join(),
        ErrorCodeEnum.QUERY_PARAM_INVALID_FAIL,
      );
    }
    return object;
  }

  private toValidate(paramMetatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(paramMetatype);
  }
}
```

注册成全局管道(`pipe`)：

```typescript
@Module({
  imports: [
    ConfigModule.forRoot({
      cache: true,
      load: [configurationYaml],
      isGlobal: true,
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return configService.get('GLOBAL_CONFIG.db.mysql');
      },
    }),
    UserModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    {
      provide: APP_PIPE,
      useClass: ValidationPipe,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor,
    },
    AppService,
  ],
})
export class AppModule {}
```



## 配置`redis`模块

安装：

```
npm install redis 
```

创建`cache`模块：

```
nest g module cache
nest g service cache
```

修改`cache.module.ts`文件内容：

```typescript
import { Module } from '@nestjs/common';
import { CacheService } from './cache.service';
import { createClient } from 'redis';
import { ConfigService } from '@nestjs/config';

@Module({
  providers: [
    CacheService,
    {
      provide: 'REDIS_CLIENT',
      inject: [ConfigService],
      async useFactory(configService: ConfigService) {
        const socket = configService.get('GLOBAL_CONFIG.db.redis');
        const client = createClient({
          socket,
        });
        await client.connect();
        return client;
      },
    },
  ],
  exports: [CacheService],
})
export class CacheModule {}
```

修改`cache.service.ts`内容：

```typescript
import { Inject, Injectable } from '@nestjs/common';
import { RedisClientType } from 'redis';
@Injectable()
export class CacheService {
  constructor(@Inject('REDIS_CLIENT') private redisClient: RedisClientType) {}

  /**
   * @description: 获取值
   * @param {*} key
   * @return {*}
   */
  async get(key) {
    let value = await this.redisClient.get(key);
    try {
      value = JSON.parse(value);
    } catch (error) {}
    return value;
  }

  /**
   * @description: 设置值
   * @param {string} key
   * @param {any} value
   * @param {number} second
   * @return {*}
   */
  async set(key: string, value: any, second?: number) {
    value = JSON.stringify(value);
    return await this.redisClient.set(key, value, { EX: second });
  }

  /**
   * @description: 删除值
   * @param {string} key
   * @return {*}
   */
  async del(key: string) {
    return await this.redisClient.del(key);
  }

  /**
   * @description: 清除缓存
   * @return {*}
   */
  async flushall() {
    return await this.redisClient.flushAll();
  }
}
```



## 登陆注册逻辑

新建文件：

```
nest g module core/modules/user
nest g service core/modules/user
```

修改`user.module.ts`文件：

```typescript
import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])], // 导入 User 实体
  controllers: [],
  providers: [UserService],
  exports: [UserService], // 把 user 模块整个导出去
})
export class UserModule {}
```

在`user`目录下新建`entities`目录， 创建`user.entity.ts`文件：

```typescript
import { BeforeInsert, Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import * as crypto from 'crypto';
import encry from '@/common/utils/crypto.util';

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
  role: string;

  @Column({ nullable: true })
  salt: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  create_time: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  update_time: Date;
}
```

用户密码需要进行加密，这里使用 `typeorm`的`beforeInsert`勾子对密码进行加盐处理，加盐的方法放在`src/common/utils/crypto.util`下：

```typescript
import * as crypto from 'crypto';

/**
 * @description: 加盐
 * @param {string} input
 * @param {string} salt
 * @return {*}
 */
export default (input: string, salt: string) => {
  return crypto.pbkdf2Sync(input, salt, 1000, 64, 'sha256').toString('hex');
};
```

需要按照`crypto`依赖。接着修改`user.service.ts`文件：

```typescript
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { APIException } from 'src/core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  /**
   * @description: 查找用户
   * @param {string} username
   * @return {*}
   */
  async findOne(username: string) {
    const user = await this.userRepository.findOne({
      where: { username },
    });

    if (!user) throw new HttpException('用户不存在', HttpStatus.BAD_REQUEST);
    return user;
  }

  /**
   * @description: 注册用户
   * @param {CreateUserDto} createUserDto
   * @return {*}
   */
  async create(createUserDto: CreateUserDto) {
    const { username } = createUserDto;
    const existUser = await this.userRepository.findOneBy({ username });

    // 业务查询异常
    if (existUser) {
      throw new APIException('用户已存在', ErrorCodeEnum.USER_EXIST);
    }

    try {
      // 创建新用户，此时还未写入到数据库
      const newUser = await this.userRepository.create(createUserDto);
      // save 调用表示写入数据库
      await this.userRepository.save(newUser);
      return '注册成功';
    } catch (error) {
      // 服务器内部出错
      throw new HttpException(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
```

`user`服务提供两个方法，`findOne`是提供给登陆接口使用的，后面会用到，`create`方法的逻辑是用来注册用户的，`user`作为工具模块，不需要对外提供路由，接着我们创建业务模块`auth`：

```
nest g res auth
```

接着安装`@nestjs/jwt`,用来生成`token`：

```
npm i @nestjs/jwt
```

接着修改`auth.module.ts`的内容：

```typescript
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from '@/core/modules/user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    UserModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      global: true,
      useFactory: (configService: ConfigService) => {
        return {
          secret: configService.get('GLOBAL_CONFIG.secret.jwt_secret'), // 从配置文件读取secret
          signOptions: {
            expiresIn: '3600s',
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
```

`auth`模块通过配置文件传入`JwtModule`模块所需要的配置，接着去定义`auth.service.ts`文件：

```typescript
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from '@/core/modules/user/dto/create-user.dto';
import { UserService } from '@/core/modules/user/user.service';
import { SigninDto } from './dto/signin.dto';
import encry from '@/common/utils/crypto.util';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * @description: 注册用户
   * @param {CreateUserDto} createUserDto
   * @return {*}
   */
  async create(createUserDto: CreateUserDto) {
    return await this.userService.create(createUserDto);
  }

  /**
   * @description: 登陆
   * @param {SigninDto} signinDto
   * @return {*}
   */
  async signin(signinDto: SigninDto) {
    const { username, password } = signinDto;
    const user = await this.userService.findOne(username);

    if (user?.password !== encry(password, user.salt)) {
      throw new HttpException('密码错误', HttpStatus.UNAUTHORIZED);
    }

    // jwt 参数
    const payload = { username: user.username, sub: user.id };

    // 生成 token
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
```

这里定义了`create` 和 `signin` 方法用来，`create` 调用的是`userService`提供的注册服务，所以记得一定要把`user`模块导出来，否则这里不能够使用`user`模块， `signin`方法是用来进行登陆，登陆合法的话，返回 `jwt`给前端。

接着定义`auth.controller.ts`文件：

```typescript
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '@/core/modules/user/dto/create-user.dto';
import { SigninDto } from './dto/signin.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() createUserDto: CreateUserDto) {
    return await this.authService.create(createUserDto);
  }

  @Post('signin')
  async signin(@Body() signinDto: SigninDto) {
    return await this.authService.signin(signinDto);
  }
}

```

对外暴露`API`给前端。



## 路由守卫验证`JWT`

注册跟登陆搞定后，需要对后续的访问进行`JWT`的验证啦。创建守卫：

```
nest g gu auth
```

然后修改`auth.guard.ts`文件：

```typescript
import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  @Inject()
  private jwtService: JwtService;

  @Inject()
  private configService: ConfigService;

  @Inject()
  private reflector: Reflector;

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 获取被public装饰器装饰的标记符号
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      // 即将调用的方法
      context.getHandler(),
      // controller类型
      context.getClass(),
    ]);

    // 不需要鉴权的接口
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      this.logger.log(`非法访问: ${request.ip}`);
      throw new HttpException('禁止访问,请联系管理员', HttpStatus.FORBIDDEN);
    }

    try {
      // 校验 token
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get('GLOBAL_CONFIG.secret.jwt_secret'),
      });
      request['user'] = payload;
    } catch {
      this.logger.log(`token校验失败: ${request.ip}`);
      throw new HttpException(
        'token校验失败,请确认token是否有效',
        HttpStatus.FORBIDDEN,
      );
    }

    return true;
  }

  /**
   * @description: 解析获取token
   * @param {Request} request
   * @return {*}
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
```

接着修改`auth.module.ts`： 

```typescript
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from '@/core/modules/user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './auth.guard';

@Module({
  imports: [
    UserModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      global: true,
      useFactory: (configService: ConfigService) => {
        return {
          secret: configService.get('GLOBAL_CONFIG.secret.jwt_secret'),
          signOptions: {
            expiresIn: '3600s',
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard, // 全局守卫
    },
  ],
})
export class AuthModule {}

```

预设系统大部分的接口都需要进行鉴权，所以直接设置成全局守卫，之后我们再自定义一个装饰器将某些接口公开，所以，创建守卫中出现的`isPublic`逻辑的文件`public.decorator.ts`：

```typescript
import { SetMetadata } from '@nestjs/common';

export const Public = () => SetMetadata('isPublic', true);
```

逻辑很简单，给公开的接口做个标记。
