export default function LoginPage() {
    return (
        <div className="w-[430px]">
            <div>
                <h1>Task Momentum</h1>

                <form>
                    <div>
                        <label htmlFor="full_name">Nome completo</label>
                        <input type="text" id="full_name" name="full_name" required />
                    </div>

                    <div>
                        <label htmlFor="email">E-mail</label>
                        <input type="email" id="email" name="email" required />
                    </div>

                    <div>
                        <label htmlFor="password">Senha</label>
                        <input type="password" id="password" name="password" required />
                    </div>

                    <button type="submit">Cadastrar</button>
                </form>

                <p>
                    Já tem cadastro? <p>Clique aqui.</p>
                </p>
            </div>
        </div>
    );
}
