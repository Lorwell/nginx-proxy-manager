import cn from "classnames";
import OverlayTrigger from "react-bootstrap/OverlayTrigger";
import Popover from "react-bootstrap/Popover";
import type { CertificateActivation } from "src/api/backend";
import { T } from "src/locale";

const STATUS: Record<string, { color: string; label: string }> = {
	verified: { color: "green", label: "certificate.activation.verified" },
	mismatch: { color: "red", label: "certificate.activation.mismatch" },
	stale: { color: "yellow", label: "certificate.activation.stale" },
	unverified: { color: "azure", label: "certificate.activation.unverified" },
	skipped: { color: "secondary", label: "certificate.activation.skipped" },
};

const DetailRow = ({ label, value }: { label: string; value?: string | null }) => {
	if (!value) return null;
	return (
		<div className="text-truncate">
			<strong>{label}:</strong> <span className="font-monospace">{value}</span>
		</div>
	);
};

export function CertificateActivationFormatter({ activation }: { activation?: CertificateActivation }) {
	if (!activation) {
		return <span className="text-muted">—</span>;
	}

	const status = STATUS[activation.status] ?? STATUS.unverified;

	const popover = (
		<Popover id="certificate-activation-popover">
			<Popover.Header>
				<T id={status.label} />
			</Popover.Header>
			<Popover.Body className="small">
				<div>
					<strong>
						<T id="certificate.activation.checked-on" />:
					</strong>{" "}
					{activation.checkedOn || "—"}
				</div>
				{activation.domain && (
					<div className="text-truncate">
						<strong>SNI:</strong> <span className="font-monospace">{activation.domain}</span>
						{activation.synthetic ? (
							<em className="ms-1">
								(<T id="certificate.activation.synthetic" />)
							</em>
						) : null}
					</div>
				)}
				<DetailRow label="notAfter" value={activation.servedNotAfter} />
				<DetailRow label="SHA-256" value={activation.servedFingerprint} />
				{activation.servedFingerprint && activation.expectedFingerprint !== activation.servedFingerprint && (
					<DetailRow label="expected" value={activation.expectedFingerprint} />
				)}
				{activation.detail && <div className="text-danger mt-1">{activation.detail}</div>}
			</Popover.Body>
		</Popover>
	);

	return (
		<OverlayTrigger trigger={["hover", "focus"]} placement="left" overlay={popover}>
			<span className={cn("status", `status-${status.color}`)}>
				<span className="status-dot" />
				<T id={status.label} />
			</span>
		</OverlayTrigger>
	);
}
