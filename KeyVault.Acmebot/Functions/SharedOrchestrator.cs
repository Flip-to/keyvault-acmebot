using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using DurableTask.TypedProxy;

using KeyVault.Acmebot.Models;

using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.DurableTask;

namespace KeyVault.Acmebot.Functions
{
    public class SharedOrchestrator
    {
        [FunctionName(nameof(IssueCertificate))]
        public async Task IssueCertificate([OrchestrationTrigger] IDurableOrchestrationContext context)
        {
            var certificatePolicy = context.GetInput<CertificatePolicyItem>();

            var activity = context.CreateActivityProxy<ISharedActivity>();

            var zones = await activity.GetZones();
            
            // ワイルドカード、コンテナ、Linux の場合は DNS-01 を利用する
            var useDns01Auth = certificatePolicy.DnsNames.Any(x => x.StartsWith("*") || zones.Any(x.EndsWith));

            // 前提条件をチェック
            if (useDns01Auth)
            {
                await activity.Dns01Precondition(certificatePolicy.DnsNames);
            }
            else
            {
                await activity.Http01Precondition(certificatePolicy.DnsNames);
            }


            // 新しく ACME Order を作成する
            var orderDetails = await activity.Order(certificatePolicy.DnsNames);

            // 既に確認済みの場合は Challenge をスキップする
            if (orderDetails.Payload.Status != "ready")
            {
                // 複数の Authorizations を処理する
                IReadOnlyList<AcmeChallengeResult> challengeResults;

                if (useDns01Auth)
                {
                    var propagationSeconds = 10;
                    // ACME Challenge を実行
                    (challengeResults, propagationSeconds) = await activity.Dns01Authorization(orderDetails.Payload.Authorizations);

                    // DNS Provider が指定した分だけ遅延させる
                    await context.CreateTimer(context.CurrentUtcDateTime.AddSeconds(propagationSeconds), CancellationToken.None);

                    // DNS で正しくレコードが引けるか確認
                    await activity.CheckDnsChallenge(challengeResults);
                }
                else
                {
                    challengeResults = await activity.Http01Authorization(orderDetails.Payload.Authorizations);

                    // HTTP で正しくアクセスできるか確認
                    await activity.CheckHttpChallenge(challengeResults);
                }

                // ACME Answer を実行
                await activity.AnswerChallenges(challengeResults);

                // Order のステータスが ready になるまで 60 秒待機
                await activity.CheckIsReady((orderDetails, challengeResults));

                if (useDns01Auth)
                {
                    // 作成した DNS レコードを削除
                    await activity.CleanupDnsChallenge(challengeResults);
                } else
                {
                    await activity.CleanupHttpChallenge(challengeResults);
                }
            }

            // Key Vault で CSR を作成し Finalize を実行
            orderDetails = await activity.FinalizeOrder((certificatePolicy, orderDetails));

            // Finalize の時点でステータスが valid の時点はスキップ
            if (orderDetails.Payload.Status != "valid")
            {
                // Finalize 後のステータスが valid になるまで 60 秒待機
                orderDetails = await activity.CheckIsValid(orderDetails);
            }

            // 証明書をダウンロードし Key Vault に保存
            var certificate = await activity.MergeCertificate((certificatePolicy.CertificateName, orderDetails));

            // 証明書の更新が完了後に Webhook を送信する
            await activity.SendCompletedEvent((certificate.Name, certificate.ExpiresOn, certificatePolicy.DnsNames));
        }
    }
}
