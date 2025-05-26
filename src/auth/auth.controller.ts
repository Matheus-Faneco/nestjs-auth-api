import { Body, Controller, Post } from '@nestjs/common';
import { SignInDTO, SignUpDTO } from './dtos/auth';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) {}

    //auth/signup
    @Post('signup')
    async signup(@Body() body: SignUpDTO) {
        return await this.authService.signup(body);
    }

    //auth/signin
    @Post('signin')
    async signin(@Body() body: SignInDTO) {
        return await this.authService.signin(body);
    }
}
