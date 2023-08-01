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

