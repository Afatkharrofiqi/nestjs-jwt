import { Injectable } from '@nestjs/common';
import { AuthDto } from 'src/dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { Tokens } from 'src/types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prismaService: PrismaService, private jwtService: JwtService) {}

  async hashData(data: string): Promise<string> {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync({
        sub: userId,
        email,
      }, {
        secret: 'at-secret',
        expiresIn: 60 * 15,
      }),
      this.jwtService.signAsync({
        sub: userId,
        email,
      }, {
        secret: 'rt-secret',
        expiresIn: 60 * 60 * 24 * 7,
      })
    ])

    return {
      access_token: at,
      refresh_token: rt
    }
  }

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);

    const newUser = await this.prismaService.user.create({
      data: {
        email: dto.email,
        hash
      }
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: number, refreshToken: string) {
    const hash = await this.hashData(refreshToken);
    await this.prismaService.user.update({
      where: {
        id: userId
      },
      data: {
        hashedRt: hash
      }
    });
  }

  signinLocal() {}

  logout() {}

  refreshTokens() {}
}
