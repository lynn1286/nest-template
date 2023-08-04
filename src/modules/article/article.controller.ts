import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { ArticleService } from './article.service';
import { CreateArticleDto } from './dto/create-article.dto';
import { UpdateArticleDto } from './dto/update-article.dto';
import { Permissions } from '@/common/decorator/permissions.decorator';

@Controller('article')
export class ArticleController {
  constructor(private readonly articleService: ArticleService) {}

  @Post()
  @Permissions('article/create')
  create(@Body() createArticleDto: CreateArticleDto) {
    return this.articleService.create(createArticleDto);
  }

  @Get()
  @Permissions('article/read')
  findAll() {
    return this.articleService.findAll();
  }

  @Get(':id')
  @Permissions('article/read')
  findOne(@Param('id') id: string) {
    return this.articleService.findOne(+id);
  }

  @Patch(':id')
  @Permissions('article/update')
  update(@Param('id') id: string, @Body() updateArticleDto: UpdateArticleDto) {
    return this.articleService.update(+id, updateArticleDto);
  }

  @Delete(':id')
  @Permissions('article/delete')
  remove(@Param('id') id: string) {
    return this.articleService.remove(+id);
  }
}
