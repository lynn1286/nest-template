import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly configService: ConfigService,
  ) {}

  @Get()
  getHello(): string {
    console.log(this.configService.get('GLOBAL_CONFIG.http.port')); // 3000
    console.log(this.configService.get('GLOBAL_CONFIG.db')); // { host: 'root', port: 3306 }

    return this.appService.getHello();
  }
}
