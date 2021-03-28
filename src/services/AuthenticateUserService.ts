import { getRepository } from 'typeorm';
import { compare } from 'bcryptjs';
import { sign } from 'jsonwebtoken';

import User from '../models/User';

interface Request {
    email: string;
    password: string;
}

interface Response {
    user: User;
    token: string;
}

class AuthenticateUserService {
    public async execute({ email, password }: Request): Promise<Response> {
        const usersRepository = getRepository(User);

        const user = await usersRepository.findOne({ where: { email } });

        if (!user) {
            throw new Error('Email or password are incorrect');
        }

        const passwordMatched = await compare(password, user.password);

        if (!passwordMatched) {
            throw new Error('Email or password are incorrect');
        }

        const token = sign({}, '0d20c655e981ca60180b45235de75bbf', {
            subject: user.id,
            expiresIn: '1d',

        });

        return { user, token };
    }
}

export default AuthenticateUserService;
