// FIXTURE: NestJS parameter decorators are sources.
//
// Same mechanism as Spring's @RequestParam: the framework binds the request
// value to the parameter before the body runs, so the decorator on the
// declaration is the only evidence in the file. The TypeScript capability
// note listed this as a gap - "a NestJS @Body() parameter is not yet
// recognised as a source".
import { Controller, Get, Post, Param, Query, Body, Headers } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('ops')
export class OpsController {
  @Get(':host')
  ping(@Param('host') host: string) {
    // EXPECT-FLOW command-injection
    exec('ping -c 1 ' + host);
  }

  @Get()
  search(@Query('q') q: string) {
    // EXPECT-FLOW command-injection
    exec('grep ' + q);
  }

  @Post()
  run(@Body() body: string) {
    // EXPECT-FLOW command-injection
    exec('sh -c ' + body);
  }

  @Get('agent')
  agent(@Headers('user-agent') agent: string) {
    // EXPECT-FLOW command-injection
    exec('log ' + agent);
  }

  // The fence: an undecorated parameter is whatever the caller passed.
  internal(host: string) {
    // EXPECT-SIGNATURE command-injection
    exec('ping -c 1 ' + host);
  }
}
