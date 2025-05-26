import { Injectable, UnauthorizedException } from '@nestjs/common';
import { SignInDTO, SignUpDTO } from './dtos/auth';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService, private jwt: JwtService){}

    async signup(data: SignUpDTO) {
        const userAlreadyExists = await this.prisma.user.findUnique({
            where: {
                email: data.email
            }
        });

        if(userAlreadyExists){
            throw new UnauthorizedException('User already exists');
        }

        const hashedPassword = await bcrypt.hash(data.password, 10)

        const user = await this.prisma.user.create({
            data: {
                name: data.name,
                email: data.email,
                password: hashedPassword
            }
        })
        return {
            message: 'User created successfully',
            id: user.id,
            name: user.name,
            email: user.email
        };
    }

    async signin(data: SignInDTO){
        const user = await this.prisma.user.findUnique({
            where: {
                email: data.email
            }
        })
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }
        
        const passwordMatch = await bcrypt.compare(data.password, user.password)

        if (!passwordMatch) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const accessToken = await this.jwt.signAsync({
            id: user.id,
            name: user.name,
            email: user.email
        })

        return {
            accessToken,
        };
    }
}
