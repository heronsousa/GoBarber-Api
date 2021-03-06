import { Router } from 'express';
import multer from 'multer';
import asyncHandler from "express-async-handler"

import uploadConfig from '../config/upload';
import CreateUserService from '../services/CreateUserService';
import UpdateUserAvatarService from '../services/UpdateUserAvatarService';
import ensureAuthenticated from '../middlewares/ensureAuthenticated';

const usersRouter = Router();
const upload = multer(uploadConfig);

usersRouter.post('/', asyncHandler(async (request, response) => {
    const { name, email, password } = request.body;

    const createUser = new CreateUserService();

    const user = await createUser.execute({
        name,
        email,
        password
    });

    delete user.password;

    return response.json(user);
}));

usersRouter.patch('/avatar', ensureAuthenticated, upload.single('avatar'), asyncHandler(async (request, response) => {
    const updateUserAvar = new UpdateUserAvatarService();

    const user = await updateUserAvar.execute({
        user_id: request.user.id,
        avatarFileName: request.file.filename
    });

    delete user.password;

    return response.json(user);
}));

export default usersRouter;
