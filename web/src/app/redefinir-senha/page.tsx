export default function LoginPage() {

    return (
        <div>
            <div>
                <h1>Task Momentum</h1>

                <form>
                    <div>
                        <label htmlFor="password">Senha</label>
                        <input type="password" id="password" name="password" required />
                    </div>

                    <button type="submit">Redefinir</button>
                </form>

            </div>
        </div>
    );
}
