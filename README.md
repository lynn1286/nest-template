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



