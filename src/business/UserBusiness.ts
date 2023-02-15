import { UserController } from "../controller/UserController"
import { UserDatabase } from "../database/UserDatabase"
import { GetUsersInput, GetUsersOutput, LoginInput, LoginOutput, SignupInput, SignupOutput } from "../dtos/UserDTO"
import { BadRequestError } from "../errors/BadRequestError"
import { NotFoundError } from "../errors/NotFoundError"
import { User } from "../models/User"
import { HashManager } from "../services/HashManager"
import { IdGenerator } from "../services/IdGenerator"
import { TokenManager } from "../services/TokenManager"
import { TokenPayload, USER_ROLES } from "../types"


export class UserBusiness {
    constructor(
        private userDatabase: UserDatabase,
        private idGenerator: IdGenerator,
        private tokenManager: TokenManager,
        private hashManager: HashManager
    ) { }

    // so vai funcionar para usuarios ADMIN
    public getUsers = async (input: GetUsersInput): Promise<GetUsersOutput> => {
        const { q, token } = input


        if (typeof q !== "string" && q !== undefined) {
            throw new BadRequestError("'q' deve ser string ou undefined")
        }

        // verificação de token 

        if (typeof token !== "string") {

            throw new BadRequestError("token esta vazio")
        }
        // verifico se token é válido 

        const payload = this.tokenManager.getPayload(token)

        if (payload === null) {
            throw new BadRequestError("token não é valido")
        }

if (payload.role!== USER_ROLES.ADMIN){

    throw new BadRequestError("Permissão não é suficiente")
}

        // se tudo der certo, coninuo o programa normalmente e faço o get

        const usersDB = await this.userDatabase.findUsers(q)

        const users = usersDB.map((userDB) => {
            const user = new User(
                userDB.id,
                userDB.name,
                userDB.email,
                userDB.password,
                userDB.role,
                userDB.created_at
            )

            return user.toBusinessModel()
        })

        const output: GetUsersOutput = users

        return output
    }

    public signup = async (input: SignupInput): Promise<SignupOutput> => {
        const { name, email, password } = input

        if (typeof name !== "string") {
            throw new BadRequestError("'name' deve ser string")
        }

        if (typeof email !== "string") {
            throw new BadRequestError("'email' deve ser string")
        }

        if (typeof password !== "string") {
            throw new BadRequestError("'password' deve ser string")
        }

        const id = this.idGenerator.generate()

const passwordHash = await this.hashManager.hash(password)

        const newUser = new User(
            id,
            name,
            email,
            passwordHash,
            USER_ROLES.NORMAL,
            new Date().toISOString()
        )

        const newUserDB = newUser.toDBModel()
        await this.userDatabase.insertUser(newUserDB)

        const tokenPayload: TokenPayload = {
            id: newUser.getId(),
            name: newUser.getName(),
            role: newUser.getRole()
        }

        const token = this.tokenManager.createToken(tokenPayload)

        const output: SignupOutput = {
            message: "Cadastro realizado com sucesso",
            token
        }

        return output
    }

    public login = async (input: LoginInput): Promise<LoginOutput> => {
        const { email, password } = input

        if (typeof email !== "string") {
            throw new Error("'email' deve ser string")
        }

        if (typeof password !== "string") {
            throw new Error("'password' deve ser string")
        }

        const userDB = await this.userDatabase.findUserByEmail(email)

        if (!userDB) {
            throw new NotFoundError("'email' não encontrado")
        }

const passwordHash = await this.hashManager.compare(password, userDB.password)

if(!passwordHash){
    throw new NotFoundError("'email' ou 'password' incorretos")
}

        // if (password !== userDB.password) {
        //     throw new BadRequestError("'email' ou 'password' incorretos")
        // }

        const user = new User(
            userDB.id,
            userDB.name,
            userDB.email,
            userDB.password,
            userDB.role,
            userDB.created_at
        )

        const payload: TokenPayload = { // carga util = é as informações mais importantes
            id: user.getId(),
            name: user.getName(),
            role: user.getRole()
        }

        const token = this.tokenManager.createToken(payload)

        const output: LoginOutput = {
            message: "Login realizado com sucesso",
            token
        }

        return output
    }
}